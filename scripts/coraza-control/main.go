// A reverse proxy fronted by the real Coraza WAF engine (the Go
// implementation of the ModSecurity rule language) running the real OWASP
// Core Rule Set.
//
// This is NOT a stand-in. Coraza evaluates actual CRS rules, and MODE selects
// its genuine SecRuleEngine setting:
//
//	MODE=detection  ->  SecRuleEngine DetectionOnly   (monitor mode: rules
//	                    evaluate and log, nothing is blocked)
//	MODE=blocking   ->  SecRuleEngine On              (rules block)
//	MODE=off        ->  SecRuleEngine Off             (CRS loaded but not
//	                    evaluated: a plain proxy control)
//
// Usage: MODE=detection ORIGIN=host:port PORT=9101 BIND=10.x.x.x go run .
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync/atomic"

	"github.com/corazawaf/coraza/v3"
	corazatypes "github.com/corazawaf/coraza/v3/types"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
)

var (
	flagged   atomic.Int64
	total     atomic.Int64
	blockedCt atomic.Int64
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	mode := env("MODE", "detection")
	origin := env("ORIGIN", "127.0.0.1:8099")
	port := env("PORT", "9101")
	bind := env("BIND", "127.0.0.1")

	var engine string
	switch mode {
	case "detection":
		engine = "DetectionOnly"
	case "blocking":
		engine = "On"
	case "off":
		engine = "Off"
	default:
		log.Fatalf("MODE must be detection|blocking|off, got %q", mode)
	}

	// Real CRS, loaded from the coraza-coreruleset module, with the engine
	// mode as the only variable between runs.
	directives := fmt.Sprintf(`
SecRuleEngine %s
SecRequestBodyAccess On
SecDebugLogLevel 0
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
`, engine)

	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithRootFS(coreruleset.FS).
			WithDirectives(directives),
	)
	if err != nil {
		log.Fatalf("coraza init: %v", err)
	}

	target, err := url.Parse("http://" + origin)
	if err != nil {
		log.Fatalf("bad ORIGIN: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		total.Add(1)
		tx := waf.NewTransaction()
		defer func() {
			tx.ProcessLogging()
			_ = tx.Close()
		}()

		tx.ProcessConnection("127.0.0.1", 0, "127.0.0.1", 0)
		tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
		// Go keeps Host out of r.Header, so it has to be added explicitly.
		// Without it CRS fires 920280 ("Request Missing a Host Header",
		// critical, 5 points) on *every* request, which alone reaches the
		// default inbound anomaly threshold -- blocking mode then 403s benign
		// traffic and detection mode flags it. That was a bug in this harness,
		// not in CRS.
		if r.Host != "" {
			tx.AddRequestHeader("Host", r.Host)
		}
		for name, values := range r.Header {
			for _, v := range values {
				tx.AddRequestHeader(name, v)
			}
		}
		if it := tx.ProcessRequestHeaders(); it != nil {
			handleInterruption(w, it, mode)
			return
		}

		if r.Body != nil {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(newReader(body))
			if len(body) > 0 {
				if _, _, err := tx.WriteRequestBody(body); err != nil {
					log.Printf("write body: %v", err)
				}
			}
		}
		// Must be called even when there is no body. CRS evaluates ARGS (so
		// query-string payloads) and runs its blocking-evaluation rules in
		// phase 2, which only executes here. Skipping it for bodyless GETs
		// meant SecRuleEngine On never blocked anything.
		if it, err := tx.ProcessRequestBody(); err != nil {
			log.Printf("process body: %v", err)
		} else if it != nil {
			handleInterruption(w, it, mode)
			return
		}

		// In DetectionOnly, Coraza matched rules and logged them but returns no
		// interruption, so the request proceeds to the origin untouched. Count
		// the match so the run can be cross-checked against what the scanner saw.
		var ids []string
		for _, mr := range tx.MatchedRules() {
			if mr.Rule().Severity() <= corazatypes.RuleSeverityWarning {
				ids = append(ids, fmt.Sprintf("%d(sev=%s)", mr.Rule().ID(), mr.Rule().Severity()))
			}
		}
		if len(ids) > 0 {
			n := flagged.Add(1)
			log.Printf("[%s] %s %s -> %v (flagged=%d/%d)",
				mode, r.Method, truncate(r.URL.String(), 60), ids, n, total.Load())
		}

		proxy.ServeHTTP(w, r)
	})

	addr := bind + ":" + port
	log.Printf("coraza control: mode=%s (SecRuleEngine %s) listening on %s -> %s",
		mode, engine, addr, origin)
	log.Fatal(http.ListenAndServe(addr, handler))
}

func handleInterruption(w http.ResponseWriter, it *corazatypes.Interruption, mode string) {
	n := blockedCt.Add(1)
	log.Printf("[%s] BLOCKED rule %d action=%s (blocked=%d)", mode, it.RuleID, it.Action, n)
	status := it.Status
	if status == 0 {
		status = http.StatusForbidden
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte("<html><body>Request blocked by security policy.</body></html>"))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

type sliceReader struct {
	b []byte
	i int
}

func newReader(b []byte) *sliceReader { return &sliceReader{b: b} }

func (r *sliceReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}
