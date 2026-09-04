# Origin-observed WAF detection — design

Status: proposed, not implemented.

## Problem

`docs/MONITOR_MODE_VALIDATION.md` establishes that five of seven supported
vendors cannot be detected from outside while configured not to block. For AWS
WAF that conclusion is now very strong: latency (n=30, bootstrap 95% CI spans
zero), response content, body-inspection limits, and 33 raw-socket parse-level
probes are all negative — with CloudWatch proving the WAF matched 23 of those
probes and forwarded them anyway.

But one row fails for a different reason than the others:

| Fastly NGWAF | Not blocking (Logging) | no | `X-SigSci-*` headers are added to requests travelling *to the origin*; clients never see them |

That is not "no signal exists." It is "the signal points away from the client."
The header is stamped as part of request handling, so it is there whether the
rule action is Log or Block. It is precisely the mode-independent artifact this
tool wants — observed from the wrong end.

**Constraint: we do not have origin log access.** So the question becomes: can
the client learn what the origin received, without cooperation from the origin?

Sometimes yes. Applications frequently reflect their received request back to
the caller. Where they do, the origin's view is readable from outside, and any
header we did not send was added by the chain in front of it.

## The insight

We do not need access to the origin. We need the origin to be **chatty**.

## Non-goals

- **Not a general solution.** This works only against targets that expose a
  header-reflecting surface. Many will not. It is opportunistic — worth a
  handful of requests, not a replacement for anything.
- **Not a fix for AWS WAF `Count`.** Reflection cannot surface a header that was
  never stamped. AWS WAF adds none. An ALB emits `X-Amzn-Trace-Id` with the
  WebACL *detached*, so that attributes the load balancer, not the WAF.
  Expected, not measured — see Testing.
- **Not a replacement for the control plane.** Where we have console or API
  access, `aws wafv2 get-web-acl-for-resource` answers this exactly, and
  `MONITOR_MODE_VALIDATION.md` is right that it is the correct instrument.
- **No exploitation.** Reading a reflected request is a GET and a string
  search. Nothing here writes, escalates, or persists.

## Design

### 1. The canary primitive

Everything below reduces to one trick. Send a request carrying a header whose
value is a unique random token:

```
X-Waf-Detect-Canary: 7f3c1e9a2b8d4f60
```

Then search the response body for that token. If it comes back, **this endpoint
reflects request headers** — and we did not need to know its output format to
find that out. Once confirmed, parse the surrounding structure for the rest of
the reflected header set.

This is format-agnostic on purpose: `phpinfo()` HTML tables, Actuator JSON, a
Django traceback, and an `httpbin` echo all differ wildly, but all of them will
contain our token verbatim if they reflect headers at all.

### 2. Acquisition, in order of how remote it is

**a. HTTP `TRACE`.** RFC 7231's method for exactly this: the server echoes the
received request in the response body. No cooperation, no discovery.

```
TRACE / HTTP/1.1
```

Mostly disabled on modern servers (Apache `TraceEnable off` by default since
2.0.55, nginx never implemented it, IIS disabled). Try it anyway — it costs one
request and answers the question completely when it works.

A note that matters: many WAFs block `TRACE` outright. A monitor-mode WAF by
definition does not. So `TRACE` succeeding *through* a suspected WAF is itself
weak evidence of non-enforcement, independent of what the echo contains.

**b. Discovered header-reflecting surfaces.** Extend
`src/effectiveness/surface_discovery.rs`, which today classifies health/status
paths, with a `ReflectsRequestHeaders` classification. Candidate paths, each
chosen because it dumps the received request:

| Path | Why it reflects |
|---|---|
| `/phpinfo.php`, `/info.php`, `/test.php` | `phpinfo()` prints `$_SERVER`, which carries every header as `HTTP_*` |
| `/actuator/httptrace`, `/actuator/env` | Spring Boot Actuator `httptrace` records recent request headers by design |
| `/debug`, `/debug/vars`, `/_debug` | Django `DEBUG=True` pages render `META`; Go `expvar` variants |
| `/headers`, `/get`, `/anything` | `httpbin`-style echo, common in internal test deployments |
| `/trace`, `/echo`, `/_echo` | ad-hoc reflectors |

Finding any of these is an information-disclosure finding in its own right and
is reported as such regardless of the WAF verdict.

**c. Reflection in ordinary application behaviour.** Anything that renders a
request header back into the page — a "your IP address is…" widget echoing
`X-Forwarded-For`, an error page quoting `User-Agent`. Narrow, but the canary
finds it for free while probing (b), since we are already looking for our token
in every response body.

**d. Operator-deployed echo (owned estate only).** If we control the
application, deploying a reflector behind the WAF makes this deterministic. Kept
as a fallback, not the primary path, given the no-log-access constraint.

```
waf-detect origin-observe <url> --echo-path /_wafdetect/echo
```

### 3. The differential

| View | Source | Gives us |
|---|---|---|
| **Sent** | what we put on the wire | ground truth for what *we* set |
| **Reflected** | canary-confirmed response body | what the origin received |
| **Origin direct** | `OriginProber`'s discovered origin IP, spoofed `Host`, same canary | control — what the origin adds by itself |

`added_by_chain = reflected − sent − origin_direct`

The third view is what stops this being "some proxy exists." Without it, every
header the origin's own stack injects reads as WAF evidence. It is optional
because the origin IP is not always discoverable; when absent, findings are
downgraded and the report says so.

### 4. Attribution — the part that must not be overclaimed

A chain-added header could come from a CDN, a load balancer, a service mesh
sidecar, or a plain reverse proxy. Two mechanisms, in order:

1. **Vendor signature table.** Only a vendor-specific prefix attributes to a
   product:

   | Prefix | Attributes to | Mode-independent? |
   |---|---|---|
   | `X-SigSci-*` | Fastly NGWAF | yes — stamped during handling |
   | `X-Wallarm-*` | Wallarm | to be verified |

   Starts deliberately small. A prefix is added only with a vendor-doc or
   measured basis recorded inline — the standard PR #59 set for the Akamai and
   CloudFlare cookies.

2. **Generic intermediary finding.** Chain-added headers with no signature match
   (`X-Forwarded-For`, `Via`, `X-Real-IP`, `X-Amzn-Trace-Id`) yield
   `IntermediaryPresent` — explicitly **not** a WAF finding. This is the
   plain-nginx row of the validation matrix, and it stays a separate category or
   the whole mode becomes a false-positive generator.

### 5. Scoring integration

Origin-observed vendor evidence is **presence, not enforcement**. It routes to
`scoring::inspection_presence_likelihood` as a third route alongside content
differential and latency, and must never touch `active_enforcement_likelihood`:
a stamped header says nothing about whether anything gets blocked.

`DetectionMethod` gains a variant so this is never confused with something a
client could normally see:

```rust
pub enum DetectionMethod {
    Header(String),
    // ...
    /// Observed in the request as it *arrived at the origin*, recovered via a
    /// reflecting surface. Different trust model from every other variant: it
    /// depends on the target disclosing its own received request.
    OriginObserved(String),
}
```

Each finding carries a caveat in the shape PR #59 established: this proves a
layer stamped the request, not that its ruleset is enabled, and not its mode.
`IntermediaryPresent` contributes zero to any WAF score.

### 6. CLI surface

```
waf-detect origin-observe <url> [--json]
waf-detect origin-observe <url> --echo-path <path> [--json]   # owned estate
```

Default run tries `TRACE`, then the discovery list, watching every response for
the canary. Per `AGENTS.md`, `agent-skills/waf-assess/WORKFLOW.md` is updated in
the same commit — including that `Inconclusive` must not be rendered as a
negative.

## Data model

```rust
pub enum ReflectionSource {
    HttpTrace,
    DiscoveredPath(String),
    IncidentalReflection(String),
    OperatorEcho(String),
}

pub enum OriginObservedOutcome {
    /// A vendor signature matched a chain-added header.
    WafAttributed { vendor: String, headers: Vec<String>, via: ReflectionSource },
    /// Chain added headers, none vendor-attributable.
    IntermediaryPresent { headers: Vec<String>, via: ReflectionSource },
    /// A reflecting surface was found and the chain added nothing.
    /// NOT proof of no WAF -- AWS WAF Count adds nothing either.
    NoChainHeaders { via: ReflectionSource },
    /// No reflecting surface found. The question could not be asked.
    NoReflectionAvailable,
}
```

`NoChainHeaders` and `NoReflectionAvailable` are separate on purpose.
Collapsing them repeats the defect PRs #62 and #65 just fixed: reporting a
measured zero and "never asked" as the same value.

## Testing

Unit tests for canary detection across fixture bodies (real `phpinfo()` HTML, an
Actuator `httptrace` JSON payload, a Django debug page), the differential
arithmetic, and the signature table — hermetic, in the style of
`src/virtual_adversary2/fixture.rs`.

### Functional acceptance — required; unit tests do not close this

Per `CLAUDE.md`, a WAF change is not done until exercised against a real
deployment.

| # | Setup | Expected |
|---|---|---|
| 1 | **Fastly NGWAF, agent in Logging mode**, `phpinfo()` reachable behind it | `WafAttributed { vendor: "Fastly NGWAF" }` from `HTTP_X_SIGSCI_*` — the case this exists for |
| 2 | Same, agent **blocking** | still `WafAttributed` — proves mode-independence |
| 3 | **Plain nginx reverse proxy**, no WAF, `phpinfo()` behind it | `IntermediaryPresent`, **never** `WafAttributed` |
| 4 | **AWS WAF on ALB, rules `Count`**, reflector behind it | `IntermediaryPresent` from `X-Amzn-Trace-Id`, not `WafAttributed` — and run **detached** too, or the AWS non-goal stays an assumption |
| 5 | Bare origin, reflector, no intermediary | `NoChainHeaders` |
| 6 | Target with no reflecting surface | `NoReflectionAvailable`, not `NoChainHeaders` |
| 7 | Origin with `TRACE` enabled behind a monitor-mode WAF | `WafAttributed` via `ReflectionSource::HttpTrace` |

Row 3 is the gate. Row 6 is the second gate — the mode must be honest about not
having been able to ask.

Local targets bind a private LAN IP and run with
`--active-target-profile internal` (see PR #64). AWS resources go in the WAF
staging account, security group restricted to a single corp `/32`, deleted
after — matching how rows 8–10 of `MONITOR_MODE_VALIDATION.md` were run.

## Open questions

1. **Is `X-Wallarm-*` real?** To be verified. Wallarm has no provider in this
   tool at all, so it may be moot until that gap closes.
2. **How often does this actually fire?** The honest answer is unknown. Worth
   measuring the hit rate for reflecting surfaces across a sample of real
   targets before investing beyond a first implementation — if it is near zero
   on hardened estate, this stays a niche tool for internal apps.
3. **Response-side stripping.** A WAF that removes origin headers (`Server`,
   `X-Powered-By`) before the client sees them is detectable by comparing the
   client response against the origin-direct response. Different differential,
   same two-vantage-point idea. Deferred.
