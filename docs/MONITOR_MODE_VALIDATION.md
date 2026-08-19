# Monitor-mode detection: what it detects, measured

`--posture --posture-va2` reports `monitor_mode_likelihood`, an estimate that a
WAF is present but not enforcing. This document records what that signal was
actually measured against, because the boundary is narrower than the feature
name suggests and it is easy to demo it wrong.

Measured 2026-08-19. Re-run any row before quoting it; WAF vendors change
implementations.

## Results

Every row is a real run of:

```
waf-detect --posture <url> --posture-va2 --posture-json
```

| # | Target | monitor_mode | enforcement | Expected | Correct? |
|---|--------|-------------:|------------:|----------|:--------:|
| 1 | Bare static origin, nothing in front | 0.000 | 0.000 | no WAF | yes |
| 2 | Plain reverse proxy, zero rules | 0.000 | 0.000 | no WAF | yes |
| 3 | Stand-in proxy: inspects + **allows** | **0.650** | 0.000 | monitor mode | yes |
| 4 | Stand-in proxy: inspects + blocks | 0.000 | 0.458 | enforcing | yes |
| 5 | Coraza + OWASP CRS, `SecRuleEngine Off` | 0.000 | 0.000 | no WAF | yes |
| 6 | Coraza + OWASP CRS, `SecRuleEngine DetectionOnly` | **0.000** | 0.000 | monitor mode | **no — missed** |
| 7 | Coraza + OWASP CRS, `SecRuleEngine On` | 0.000 | 0.382 | enforcing | yes |
| 8 | AWS WAF on ALB, WebACL detached | 0.000 | 0.000 | no WAF | yes |
| 9 | AWS WAF on ALB, managed rules `Count` | **0.000** | 0.000 | monitor mode | **no — missed** |
| 10 | AWS WAF on ALB, managed rules blocking | 0.000 | 0.246 | enforcing | yes |

Rows 5–7 use real Coraza (the Go implementation of the ModSecurity rule
language) with the real OWASP Core Rule Set; harness in
`scripts/coraza-control/`. Rows 8–10 use real AWS WAF with
`AWSManagedRulesCommonRuleSet` + `AWSManagedRulesSQLiRuleSet` on an ALB with a
fixed-response listener, `OverrideAction: Count` for row 9. Managed rule groups
were used rather than hand-written rules so the test could not be tuned to the
scanner's own probes. `CloudWatchMetrics` confirmed row 9 was genuinely
counting (`CountedRequests` > 0, `BlockedRequests` 0).

Rows 1–4 use `scripts/monitor_mode_control_proxy.py`.

## What this establishes

**No false positives.** All seven non-monitor-mode rows read 0.000 monitor
mode, including two real-WAF products and a plain reverse proxy. That last one
matters most: a detector that fires on any inspecting intermediary would fire
on plain nginx, and would be worse than the false negative it replaced.

**Enforcement is detected without a vendor signature.** Rows 9 and 10 are
AWS WAF, which leaves no identifying response header at all — passive detection
reported `waf=None, confidence=0.0`. Row 10's enforcement estimate came purely
from behavior.

**Monitor mode is detected only when it leaves a remote trace.** Row 3 is
detected because the inspecting layer pays ~60ms on flagged requests. Rows 6
and 9 are missed.

## Why rows 6 and 9 are missed

Not a scoring bug. There is nothing remotely observable.

**Row 6 (Coraza `DetectionOnly`)** — evaluates the full CRS in well under a
millisecond and, being detection-only, changes nothing about the response.
Per-pair deltas came back as noise (`[6, -4, -13, 1, 3, -7]` ms) with zero
header, body, or status differences.

**Row 9 (AWS WAF `Count`)** — same shape, and this one was tested harder
because a network-hop WAF was expected to be the case that *works*. Per-pair
deltas from the scanner were `[2, 3, 3, -1, -2]` ms. A dedicated 30-pair
length-matched measurement gave:

```
median delta = +1.39 ms    MAD = 3.02 ms    positive = 18/30 (60%)
bootstrap 95% CI of the median = [-0.80, +2.64] ms   <- includes zero
```

So AWS WAF's Count-mode inspection cost is **not statistically distinguishable
from zero** even at n=30. This is not a sample-size limitation — more samples
will not recover a signal whose confidence interval spans zero. Lowering
`LATENCY_NOISE_FLOOR_MS` below 15ms to chase it would manufacture false
positives: the bare-origin control in row 1 showed per-pair deltas up to 16ms
from connection effects alone, with no WAF present.

Also tested and ruled out for these rows:

- **Response content** — no header, cookie, body-length, or status difference
  on flagged requests in either product's monitor mode.
- **Body inspection limits**, on the theory that they are enforced
  independently of `SecRuleEngine`: a 250KB urlencoded body returned 200 in all
  three Coraza modes.

## Honest scope

The signal detects monitor-mode inspection that either **costs** something
observable (roughly >=15ms on flagged requests) or **changes** the response.
That covers deployments where inspection means body buffering, an extra proxy
hop, or a WAF attaching a cookie or header — Imperva's `incap_ses` and
challenge-injecting CDN WAFs are in this class.

It does **not** detect an inline, optimized, silent engine in monitor mode.
Both products tested here fall in that class. Do not claim coverage of
"WAF in monitor mode" generally.

## Not yet tested

- Cloudflare, Akamai, Imperva, F5 in monitor/log-only mode. These attach
  cookies or headers more often than AWS WAF does, so the content route may
  reach them where latency does not — but that is a prediction, not a
  measurement.
- WAFs configured with request-body inspection enabled, where buffering cost is
  larger and more likely to clear the floor.

## Known reporting gap this exposes

For rows 6 and 9 the tool emits `monitor_mode_likelihood: 0.000`, which reads
as "not in monitor mode" when the truthful answer is "cannot determine". The
field is emitted unconditionally even when no enforcement evidence was
collected. Distinguishing "measured zero" from "no measurement" needs an
`Option<f64>` or an accompanying flag in `PostureReport`. Until that exists,
treat a 0.000 as inconclusive rather than negative.

## Next angle, if this matters

Normalization side effects rather than cost or content. An inspecting layer has
to parse and re-serialize the request, so malformed input — conflicting
`Content-Length`/`Transfer-Encoding`, oversized headers, `%2e%2e%2f` path
segments, absolute-form request URIs — tends to produce an error fingerprint
distinct from the origin's own. That happens in the parser, so it is
independent of whether the rule engine is in detection-only mode. It carries
its own false-positive surface: plain nginx normalizes paths too, which is the
same proxy-vs-WAF trap rows 2 and 5 exist to catch.

## Per-vendor: is monitor mode remotely detectable at all?

Covering the WAFs supported at Adobe. "Remotely detectable" means: from
outside, with no console or API access, can we tell a WAF is present while it
is configured not to block?

| Vendor | Its monitor mode | Detectable? | Signal, or why not | Basis |
|--------|------------------|:-----------:|--------------------|-------|
| **Akamai** | alert-only | **yes** | Bot Manager cookies `_abck`, `ak_bmsc`, `bm_sz`, `bm_sv`, `bm_mi` — set as part of normal handling, whether rules alert or deny | vendor + community docs |
| **CloudFlare** | log | **yes** | `__cf_bm`, set whenever Bot Management / Bot Fight Mode is enabled, independent of any challenge. (`cf-mitigated` means it *acted* — enforcement, not presence) | CloudFlare docs; live-verified |
| AWS WAF | `Count` | no | Inspection costs ~1.4ms and nothing about the response changes | **measured**, rows 8–10 above |
| ModSecurity | `DetectionOnly` | no | Sub-millisecond inline evaluation, response unchanged | **measured**, rows 5–7 above |
| Azure | Detection | no | "the client receives the normal response as if the WAF rule didn't trigger" | Microsoft docs |
| Fastly NGWAF | Not blocking (Logging) | no | `X-SigSci-*` headers are added to requests travelling *to the origin*; clients never see them | Fastly docs |
| Wallarm | monitoring | no | No documented client-visible artifact; NGINX-based, and Wallarm's own guidance is to strip version headers | Wallarm docs |

Note on what the two "yes" rows prove: the vendor's **bot-management** module is
engaged. Not that the WAF ruleset (Akamai App & API Protector, CloudFlare
managed rules) is enabled, and not its mode. A site can run Bot Manager with
AAP switched off. The scan attaches a caveat saying exactly that; do not quote
these as "WAF ruleset in alert mode".

Separately: **Wallarm has no provider in this tool at all**, which is a
coverage gap independent of monitor mode.

## Consequence: for owned estate, ask the control plane

Five of seven cannot be answered from outside. For infrastructure we own, that
question has an exact answer available over an API rather than an inferred one:

- AWS: `aws wafv2 list-web-acls` → `get-web-acl` and
  `get-web-acl-for-resource`, then read each rule's `Action` / a rule group's
  `OverrideAction` for `Count`. AWS Firewall Manager covers this across
  accounts, and Adobe has a Firewall Manager account.
- Azure: the WAF policy's `policySettings.mode` is `Detection` or `Prevention`.
- Fastly NGWAF: the corp/site API reports agent mode.
- Wallarm: the node's filtration mode is readable from its API.

This is the reliable way to answer "which of our WAFs are not enforcing", and
it is not what a black-box scanner can do. Tracked as an open item in
DEVELOPMENT.md.
