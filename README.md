# WAF Detector

A high-performance tool for detecting, testing, and profiling Web Application Firewalls (WAFs) and Content Delivery Networks (CDNs). Built for security engineers who need to validate their defensive infrastructure.

> **Important:** Only use against systems you own or have explicit authorization to test. Unauthorized scanning may violate terms of service or laws in your jurisdiction.

## What It Does

| Mode | What it tests | Flag |
|------|--------------|------|
| **Detection** | Identifies which WAF/CDN protects a target | `waf-detect <url>` |
| **Smoke Test** | Sends known attack payloads, measures block rates | `--smoke-test <url>` |
| **Enforcement Test** | Sends categorized attack probes, measures block/challenge/allow | `--va <url>` |
| **Behavioral Analysis** | Paired probes testing WAF sophistication across 5 channels | `--va2 <url> --va2-run` |
| **Posture Report** | Unified grade (A-F) combining all test results | `--posture <url>` |
| **TUI** | Interactive terminal dashboard with live scan results | `--tui <url>` |

## Quick Start

```bash
# Build
cargo build --release

# Detect WAF/CDN
./target/release/waf-detect example.com

# Run smoke test
./target/release/waf-detect --scope init example.com
./target/release/waf-detect --smoke-test example.com

# Full posture report (detection + behavioral analysis)
./target/release/waf-detect --posture example.com --posture-va2 --posture-json

# Interactive TUI
./target/release/waf-detect --tui example.com
```

## Detection

Identifies WAF and CDN providers using HTTP headers, response bodies, DNS records, timing analysis, and TLS certificates.

**Supported providers:** CloudFlare, AWS WAF, Akamai, Fastly, Vercel, Azure, F5 BIG-IP

```bash
# Single URL
./target/release/waf-detect example.com

# Multiple URLs
./target/release/waf-detect example.com google.com cloudflare.com

# Batch from file
./target/release/waf-detect @urls.txt

# JSON output
./target/release/waf-detect example.com --json

# With payload-based analysis (adds detection signals)
./target/release/waf-detect example.com --payload-analysis
```

## Smoke Test

Sends known attack payloads and measures what the WAF blocks, challenges, or allows through. Active smoke testing only runs against registered owned targets.

```bash
./target/release/waf-detect --smoke-test example.com

# Aggressive mode (more payloads)
./target/release/waf-detect --smoke-test example.com --aggressive

# Export results
./target/release/waf-detect --smoke-test example.com -o results.json
```

**Attack categories tested:** SQL injection (basic + advanced), XSS (basic + advanced), command injection, path traversal, SSTI, SSRF, Log4Shell, file upload, scanner detection, GraphQL injection, HTTP request smuggling, prototype pollution, WebSocket injection, enumeration.

**Result classifications:**
- `BLOCKED` — WAF blocked the request (typically 403)
- `CHALLENGE` — Bot protection triggered (JS challenge, CAPTCHA)
- `ALLOWED` — Request passed through to the origin
- `ERROR` — Non-blocking failure (404, 500, timeout)

## Enforcement Test

Sends categorized attack probes and measures block/challenge/allow rates with confidence scoring. Requires registered target scope.

```bash
# Register owned targets once
./target/release/waf-detect --scope init example.com

# Run enforcement test
./target/release/waf-detect --va https://example.com

# With JSON output
./target/release/waf-detect --va https://example.com --va-json

# Save report
./target/release/waf-detect --va https://example.com --va-output report.json
```

**Options:**
- `--va-tier 1|2|3` — Safety tier (1 = safest)
- `--va-budget N` — Max requests per run (default: 120)
- `--va-timeout SECONDS` — Per-request timeout (default: 15)
- `--va-delay MS` — Delay between requests (default: 750)
- `--va-variants N` — Variants per payload template (default: 4)
- `--va-replay` — Export replay plan as JSON
- `--va-replay-csv` — Export replay plan as CSV

## Behavioral Analysis

Tests WAF sophistication by sending paired probes — one benign, one malicious — across 5 HTTP channels. Measures whether the WAF treats them differently.

```bash
# Dry run (shows plan without executing)
./target/release/waf-detect --va2 https://example.com

# Run behavioral analysis
./target/release/waf-detect --va2 https://example.com --va2-run

# Full 5-phase analysis
./target/release/waf-detect --va2 https://example.com --va2-run \
  --va2-phases baseline,protocol-variance,state-escalation,behavioral-pressure,challenge-interaction

# Save results
./target/release/waf-detect --va2 https://example.com --va2-run --va2-output results.json
```

**What it measures:**

| Signal | What it tests |
|--------|--------------|
| Encoding Defense | Does the WAF normalize encoded paths before matching? |
| Session Tracking | Does the WAF track session state and escalate on repeat abuse? |
| Bot Challenge | Does the WAF issue CAPTCHA or JS challenges? |
| Rate Limiting | Does the WAF throttle rapid requests? |
| Attack Recognition | Does the WAF distinguish attack probes from benign requests? |

**Channels tested:** Path, Query, Header, Body, Method. Channels with 0% attack detection are flagged as unprotected.

**Options:**
- `--va2-phases LIST` — Phases to run (comma-separated)
- `--va2-seed N` — Deterministic seed for reproducible results (default: 1337)
- `--va2-budget N` — Request budget (default: 60)
- `--va2-json` — Print plan/report as JSON

## Posture Report

Generates a unified security grade (A-F) and risk score (0-100) combining detection confidence, enforcement results, and behavioral analysis.

```bash
# Detection only
./target/release/waf-detect --posture example.com

# Include behavioral analysis
./target/release/waf-detect --posture example.com --posture-va2

# JSON output
./target/release/waf-detect --posture example.com --posture-va2 --posture-json
```

**Grade scale:**
- **A** (0-20 risk) — Strong protection across all dimensions
- **B** (21-40) — Good protection with minor gaps
- **C** (41-60) — Moderate protection, notable weaknesses
- **D** (61-80) — Weak protection, significant gaps
- **F** (81-100) — Minimal or no effective protection

## TUI (Terminal Dashboard)

Interactive terminal interface with live scan results, signal bars, findings, and keyboard navigation.

```bash
# Launch with target
./target/release/waf-detect --tui example.com

# Launch in review mode (load last saved report)
./target/release/waf-detect --tui
```

**Keyboard shortcuts:**
- `1-7` — Switch views (Dashboard, Detection, Smoke, Enforce, Behav., Findings, Log)
- `r` — Run full scan
- `j/k` — Navigate items
- `Enter` — Expand selected item
- `e` — Export report to JSON
- `?` — Toggle info tooltip
- `q` — Quit

## Target Scope

Smoke test, payload analysis, enforcement, behavioral analysis, and effectiveness testing require registered owned targets.

```bash
# Check target scope
./target/release/waf-detect --scope

# Initialize target scope
./target/release/waf-detect --scope init example.com api.example.com

# Add authorized target
./target/release/waf-detect --scope add-target admin.example.com

# Remove target
./target/release/waf-detect --scope remove-target api.example.com

# Clear target scope
./target/release/waf-detect --scope clear
```

## Interpreting Results

**Risk scores (posture report):**
- **0-25** — Low risk, WAF well-configured
- **25-50** — Medium risk, some gaps detected
- **50-75** — High risk, significant security gaps
- **75-100** — Critical risk, WAF misconfigured or ineffective

**Common findings:**
- High block rate (>90%) — Well-configured WAF
- Low block rate (<50%) — WAF may be in detection-only mode
- Unprotected channels — WAF doesn't inspect attacks in that HTTP channel
- No bot challenges — Automated attacks proceed without friction
- No rate limiting — Brute-force attacks face no throttling
- Identical responses — Target may serve only static content

## Additional Commands

```bash
# List supported providers
./target/release/waf-detect --list

# Effectiveness testing (advanced evasion techniques)
./target/release/waf-detect --effectiveness example.com

# Benchmark against corpus
./target/release/waf-detect --benchmark corpus.json

# Performance snapshot
./target/release/waf-detect example.com --perf-report perf.json

# Debug output
./target/release/waf-detect example.com --debug --verbose
```

## Development

```bash
# Build
cargo build --release

# Run tests
cargo test --all

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt
```

**Branch workflow:** `main` is protected. Use feature branches (`feature/name`) and pull requests.

## License

MIT OR Apache-2.0
