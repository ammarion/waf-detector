#!/usr/bin/env python3
"""Control reverse proxy for validating monitor-mode WAF detection.

NOT a WAF. A deliberately minimal stand-in that isolates one variable: whether
an intermediary inspects attack-shaped requests, and what it does when it finds
one. Used to get ground truth that public targets cannot give.

MODE=plain   pass-through. No inspection, no delay. An intermediary that is
             emphatically not a WAF -- the control that catches a detector
             which is really just finding reverse proxies.
MODE=monitor inspects, logs, and *allows*. Adds only the inspection latency;
             the response is byte-identical to the origin's, with no extra
             header or cookie. The hardest realistic monitor-mode case.
MODE=block   inspects and returns 403 on a match.

Usage: MODE=monitor ORIGIN=host:port PORT=8100 python3 control_proxy.py
"""
import os
import re
import sys
import time
import http.client
from urllib.parse import unquote_plus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODE = os.environ.get("MODE", "plain")
ORIGIN = os.environ.get("ORIGIN", "127.0.0.1:8099")
PORT = int(os.environ.get("PORT", "8100"))
BIND = os.environ.get("BIND", "127.0.0.1")
# Inspection cost paid per flagged request, in seconds.
INSPECT_SECONDS = float(os.environ.get("INSPECT_SECONDS", "0.060"))

ATTACK_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"<script", r"javascript:", r"onerror\s*=", r"onload\s*=",
        r"union\s+select", r"'\s*or\s*'?1'?\s*=\s*'?1", r"\bor\s+1\s*=\s*1",
        r"sleep\s*\(", r"benchmark\s*\(", r"waitfor\s+delay",
        r"\.\./", r"%2e%2e", r"/etc/passwd", r"c:\\windows",
        r";\s*(cat|ls|id|whoami|curl|wget)\b", r"\$\(", r"`",
        r"\bexec\b", r"\bxp_cmdshell\b", r"<!ENTITY", r"\{\{.*\}\}",
    )
]

FLAGGED = 0
TOTAL = 0


def looks_like_attack(path, headers, body):
    # Real WAFs normalize before matching; percent-decode so an encoded
    # payload is not trivially invisible to the control.
    haystack = [path, unquote_plus(path)]
    for name, value in headers.items():
        haystack.append(f"{name}: {value}")
    if body:
        haystack.append(body.decode("utf-8", "replace"))
    blob = "\n".join(haystack)
    for pattern in ATTACK_PATTERNS:
        if pattern.search(blob):
            return pattern.pattern
    return None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "control-proxy"
    sys_version = ""

    def log_message(self, fmt, *args):  # keep stderr readable
        pass

    def _handle(self):
        global FLAGGED, TOTAL
        TOTAL += 1
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""

        matched = None
        if MODE in ("monitor", "block"):
            matched = looks_like_attack(self.path, self.headers, body)
            if matched:
                FLAGGED += 1
                # Inspection is not free. This is the entire signal in
                # monitor mode: the request was read, then allowed.
                time.sleep(INSPECT_SECONDS)
                print(
                    f"[{MODE}] flagged {self.command} {self.path[:80]} "
                    f"(pattern={matched}) flagged={FLAGGED}/{TOTAL}",
                    file=sys.stderr,
                    flush=True,
                )

        if MODE == "block" and matched:
            page = b"<html><body>Request blocked by security policy.</body></html>"
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)
            return

        try:
            conn = http.client.HTTPConnection(ORIGIN, timeout=10)
            fwd = {k: v for k, v in self.headers.items() if k.lower() != "host"}
            conn.request(self.command, self.path, body=body or None, headers=fwd)
            upstream = conn.getresponse()
            payload = upstream.read()
            self.send_response(upstream.status)
            for name, value in upstream.getheaders():
                if name.lower() in ("transfer-encoding", "content-length", "connection"):
                    continue
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            conn.close()
        except Exception as err:  # origin unreachable
            msg = f"upstream error: {err}".encode()
            self.send_response(502)
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_PATCH = do_OPTIONS = _handle


if __name__ == "__main__":
    print(
        f"control proxy mode={MODE} listening on {BIND}:{PORT} -> {ORIGIN}",
        file=sys.stderr,
        flush=True,
    )
    ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()
