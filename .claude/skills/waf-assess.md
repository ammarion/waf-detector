---
name: waf-assess
description: Run comprehensive WAF security assessments, analyze results, and propose vendor-specific remediation rules
user_invocable: true
---

# WAF Security Assessment Agent

You are orchestrating a comprehensive WAF security assessment using the `waf-detect` CLI. You run the full scan pipeline, explain results as they arrive, generate a structured markdown report, and propose WAF-vendor-specific remediation rules.

---

## Section 1 — CLI Reference

Binary: `./target/release/waf-detect` (or `cargo run --release --`)

### Core Detection

```
waf-detect <targets...>
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `targets` | | | Domain names, URLs, or `@file.txt` to scan (positional, multiple) |
| `--json` | | false | Output results in JSON format |
| `--yaml` | | false | Output results in YAML format |
| `--compact` | `-c` | false | Compact one-line output format |
| `--debug` | `-d` | false | Show detailed debug information |
| `--verbose` | `-v` | false | Show verbose scanning progress |
| `--payload-analysis` | | false | Enable active payload-based probing during detection (authorized targets only) |
| `--list` | | false | List available detection providers |

### TUI / Web Server

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--tui` | | false | Launch interactive TUI with navigable scan results |
| `--web` | `-w` | false | Start web server mode with dashboard |
| `--port` | `-p` | 8080 | Port for web server |

Note: `--tui` conflicts with `--web`, `--json`, `--yaml`.

### Smoke Testing

```
waf-detect --smoke-test <url>
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--smoke-test` | | false | Run comprehensive WAF effectiveness smoke test |
| `--output` | `-o` | | Export results to JSON file |
| `--header` | `-H` | | Custom headers (format: `Key: Value`, repeatable) |
| `--aggressive` | | false | Enable aggressive testing mode (more payloads, faster) |

### VA1 Enforcement Testing

```
waf-detect --va <url>
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--va` | | | Run Virtual Adversary effectiveness validation (requires consent) |
| `--va-tier` | | 1 | Safety tier (1-3) |
| `--va-budget` | | 120 | Max total requests |
| `--va-timeout` | | 15 | Per-request timeout in seconds |
| `--va-delay` | | 750 | Delay between requests in milliseconds |
| `--va-variants` | | 4 | Max variants per payload |
| `--va-json` | | false | Print VA report JSON to stdout |
| `--va-output` | | | Write VA report JSON and summary to file |
| `--va-replay` | | false | Print VA replay plan JSON to stdout |
| `--va-replay-csv` | | false | Print VA replay plan CSV to stdout |
| `--va-dry-run` | | false | Print planned payloads without executing |
| `--va-top` | | 3 | Number of VA results to print |
| `--va-reason-level` | | 1 | Reason verbosity (0=none, 1=default) |
| `--va-max-len` | | 80 | Max payload length to print in output |
| `--va-schema` | | false | Print VA report JSON schema |

### VA1 Replay

```
waf-detect --va-replay-run <file.json>
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--va-replay-run` | | | Run a saved VA replay plan from a JSON report |
| `--va-replay-target` | | | Override target URL for replay run |

### VA2 Behavioral Profiling

```
waf-detect --va2 <url>              # dry run (plan only)
waf-detect --va2 <url> --va2-run    # execute campaign
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--va2` | | | Run Virtual Adversary 2.0 behavioral campaign |
| `--va2-run` | | false | Execute VA2 campaign plan (requires consent) |
| `--va2-dry-run` | | false | Print VA2 plan summary without execution |
| `--va2-json` | | false | Print VA2 plan JSON to stdout |
| `--va2-output` | | | Write VA2 plan JSON to file |
| `--va2-phases` | | `baseline,protocol-variance` | Phases to run (comma-separated) |
| `--va2-seed` | | 1337 | Deterministic seed |
| `--va2-budget` | | 60 | Request budget |

Available phases: `baseline`, `protocol-variance`, `state-escalation`, `behavioral-pressure`, `challenge-interaction`

### Posture Report

```
waf-detect --posture <url>
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--posture` | | | Generate unified posture report |
| `--posture-va2` | | false | Include VA2 behavioral profiling (requires consent) |
| `--posture-json` | | false | Output posture report as JSON |
| `--posture-summary` | | | Generate posture summary JSON (requires `WAF_DETECTOR_POSTURE_SUMMARY=1` env var) |

### Effectiveness Testing

```
waf-detect --effectiveness <url>
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--effectiveness` | | | Run comprehensive WAF effectiveness testing (requires consent) |
| `--effectiveness-config` | | | Path to TOML config overrides |
| `--effectiveness-similarity-threshold` | | | Response body similarity threshold (0.0-1.0) |
| `--effectiveness-reduction-ratio` | | | Response body reduction ratio (0.0-1.0) |
| `--effectiveness-min-length-diff` | | | Minimum response body length diff |

### Consent Management

```
waf-detect --consent                     # show consent status
waf-detect --consent request             # request user consent
waf-detect --consent status              # check status
waf-detect --consent add-target <domain> # authorize a target
waf-detect --consent remove-target <domain>
waf-detect --consent revoke              # revoke all consent
```

### Benchmark

```
waf-detect --benchmark <corpus.json>
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--benchmark` | | | Run offline detection benchmark against labeled corpus |
| `--benchmark-output` | | | Save benchmark results as JSON |
| `--benchmark-workers` | | 3 | Number of concurrent detection workers |
| `--benchmark-mode` | | `live` | Execution mode: `live` or `fixture` |
| `--benchmark-fixtures` | | | Directory containing benchmark fixture corpus |

### Performance Reporting

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--perf-report` | | | Write performance snapshot (p95/p99) to JSON file |

---

## Section 2 — Assessment Pipeline

When the user invokes `/waf-assess <target>`, follow these steps in order. After each step, print a brief status summary before proceeding to the next.

### Step 1: Build

Check if the binary exists and is up to date:

```bash
# Check if binary exists
ls -la ./target/release/waf-detect

# If missing or source is newer, rebuild
cargo build --release
```

If the build fails, stop and report the error.

### Step 2: Consent Check

```bash
./target/release/waf-detect --consent
```

Parse the output. If consent has not been granted:
1. Explain to the user that VA1, VA2, and effectiveness testing require explicit consent
2. Ask the user if they want to proceed with `--consent request`
3. If yes, run:
   ```bash
   ./target/release/waf-detect --consent request
   ```
4. Add the target domain:
   ```bash
   ./target/release/waf-detect --consent add-target <domain>
   ```

If consent is already active, verify the target domain is authorized. Add it if needed.

### Step 3: Detection

```bash
./target/release/waf-detect <url> --json
```

Parse the JSON output. Extract:
- Detected WAF/CDN name
- Confidence score (%)
- Evidence count and evidence details
- Provider type (WAF, CDN, or Both)

Print summary: `Detected: {waf_name} ({confidence}%) with {evidence_count} evidence items`

### Step 4: Smoke Test

```bash
./target/release/waf-detect --smoke-test <url> --aggressive -o /tmp/smoke-results.json
```

Parse `/tmp/smoke-results.json`. Extract:
- Total tests, blocked count, allowed count, challenge count
- Effectiveness percentage
- WAF mode (blocking, detection-only, etc.)
- Top unblocked payloads by category

Print summary: `Smoke test: {blocked}/{total} blocked ({effectiveness}%), WAF mode: {mode}`

### Step 5: VA1 Enforcement

```bash
./target/release/waf-detect --va <url> --va-json --va-tier 1 --va-budget 120
```

Parse the JSON output. Extract:
- Enforcement level
- Blocked/challenge/allowed/error counts
- Confidence score
- Risk label
- Per-category breakdown (SemanticDrift, ProtocolMutation, EncodingBypass, StructuralAbuse)

Print summary: `VA1 enforcement: {enforcement_level}, {blocked} blocked / {allowed} allowed, confidence: {score}`

### Step 6: VA2 Behavioral Profiling

```bash
./target/release/waf-detect --va2 <url> --va2-run --va2-phases baseline,protocol-variance,state-escalation,behavioral-pressure,challenge-interaction --va2-budget 60
```

Capture stdout. Extract:
- WBF signal scores (normalization, statefulness, challenge, throttle, differential)
- PMI score and label
- Channel coverage (Path, Query, Header, Body, Method)
- Per-channel discrimination rates
- Blind spots (channels with 0% discrimination)

Print summary: `VA2 behavioral: PMI {pmi} ({label}), blind spots: {blind_spots or "none"}`

### Step 7: Posture Report

```bash
./target/release/waf-detect --posture <url> --posture-va2 --posture-json
```

Parse the JSON output. Extract:
- Overall grade (A-F)
- Risk score (0-100)
- Summary narrative

Print summary: `Posture: Grade {grade}, Risk {risk_score}/100`

### Step 8: Generate Report

After all scans complete, generate the structured markdown report (see Section 3) and present it to the user. Then propose remediation rules (see Section 4) for every Critical and Medium finding.

---

## Section 3 — Report Template

IMPORTANT: The report MUST be table-driven and scannable. No essay paragraphs. Every data point goes in a table. Use box-drawing headers for visual separation. Keep explanations to single-line notes below tables.

After all scans complete, generate this exact structure:

### Block 1: Header Banner

```
╔══════════════════════════════════════════════════════════════════════════════╗
║              WAF SECURITY ASSESSMENT: {target}                              ║
║              Date: {YYYY-MM-DD HH:MM UTC}                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### Block 2: Executive Summary Table

| Metric | Value | Rating |
|--------|-------|--------|
| Detected WAF/CDN | {name} | {confidence}% confidence |
| Posture Grade | **{grade}** | Risk: {risk_score}/100 |
| Smoke Effectiveness | **{effectiveness}%** | {blocked}/{total} blocked |
| VA1 Enforcement | {enforcement} | {context note} |
| VA2 PMI | **{pmi}/100** | {label} |
| WAF Mode | {mode} | {one-line description} |

### Block 3: Detection Evidence Table

| # | Method | Signal | Confidence |
|---|--------|--------|:----------:|
{for each UNIQUE evidence: index, method type, raw signal, confidence %}

### Block 4: Smoke Test Category Scorecard

| Category | Blocked/Total | Rate | Verdict |
|----------|:-------------:|:----:|---------|
{for each category, sorted by rate descending: name, blocked/total, percentage, STRONG/GOOD/MODERATE/WEAK/POOR/NONE}

Verdict thresholds: 100%=STRONG, 80-99%=GOOD, 60-79%=MODERATE, 40-59%=WEAK, 1-39%=POOR, 0%=NONE

### Block 5: VA1 Enforcement Table

| Category | Blocked | Challenge | Allowed | Errors |
|----------|:-------:|:---------:|:-------:|:------:|
{for each VA1 category: counts}
| **Total** | **{blocked}** | **{challenge}** | **{allowed}** | **{errors}** |

> {one-line contextual note about VA1 results}

### Block 6: VA2 WBF Signals Table

Use a visual bar for each signal (10 chars: `#` for filled, `.` for empty, proportional to score).

| Signal | Score | Bar | Assessment |
|--------|:-----:|-----|-----------|
| Normalization | **{score}** | {bar} | {one-line meaning} |
| Differential | **{score}** | {bar} | {one-line meaning} |
| Throttle | {score} | {bar} | {one-line meaning} |
| Statefulness | {score} | {bar} | {one-line meaning} |
| Challenge | {score} | {bar} | {one-line meaning} |

Sort by score descending.

### Block 7: VA2 Channel Coverage Table

| Channel | Disc. % | Tested | Blind Spot? |
|---------|:-------:|:------:|:-----------:|
{for each channel: discrimination rate, pairs tested, yes/no/unknown}

> {one-line note about early stopping or budget constraints}

### Block 8: VA2 Paired Control Detail

| Control Request | Attack Probe | Control | Probe | Outcome |
|----------------|--------------|:-------:|:-----:|---------|
{for each executed pair: control description, probe description, control status, probe status, DETECTED/NOT_DETECTED/INCONCLUSIVE}

### Block 9: Findings Summary Table

| # | Severity | Finding | Source | Pass Rate |
|---|----------|---------|--------|:---------:|
{for each finding sorted by severity then pass rate: number, CRITICAL/MEDIUM/LOW, title, source, metric}

### Block 10: Remediation Rules Tables

Split into CRITICAL (immediate) and MEDIUM (hardening) sections. Each is a table:

#### CRITICAL — Immediate Action

| # | Finding | Akamai Rule | Config |
|---|---------|-------------|--------|
{for each critical finding: number, title, rule type, one-line config summary}

#### MEDIUM — Hardening

| # | Finding | Akamai Rule | Config |
|---|---------|-------------|--------|
{for each medium finding: number, title, rule type, one-line config summary}

Replace "Akamai" with detected WAF vendor name. Use the vendor-specific rule format from Section 4.

### Block 11: Expected Impact Table

| Metric | Current | After Remediation (est.) |
|--------|---------|--------------------------|
| Posture Grade | {current} | **{estimated}** |
| Risk Score | {current} | **{estimated}** |
| Smoke Effectiveness | {current}% | **{estimated}%** |
| PMI | {current} ({label}) | **{estimated} ({label})** |

### Block 12: Caveat Footer

> {one-line caveat about origin health, staging validation, rate limit tuning, etc.}

---

## Section 4 — WAF-Vendor Rule Generation

Based on the detected WAF, generate remediation rules in the vendor's native configuration format.

### Vendor Rule Formats

| Detected WAF | Rule Format |
|-------------|-------------|
| CloudFlare | Firewall Rules (expression syntax), Rate Limiting Rules, WAF Managed Rules |
| AWS | AWS WAF WebACL rules — ByteMatchStatement, SqliMatchStatement, XssMatchStatement, Rate-based |
| Akamai | App & API Protector / Kona Site Defender rules |
| Azure | Azure Front Door custom WAF rules, OWASP managed rule sets |
| F5 | BIG-IP ASM attack signatures, violation policies, iRules |
| Fastly | VCL-based WAF rules, Signal Sciences |
| Vercel | Firewall rules (limited scope — note limitations clearly) |
| Imperva | Incapsula WAF custom rules, security rules |
| ModSecurity | SecRule directives (CRS format) |
| Sucuri | Sucuri WAF custom rules |
| Radware | AppWall / DefensePro rules |
| FortiWeb | FortiWeb WAF policies |
| Unknown/None | ModSecurity CRS as universal fallback |

### Finding-to-Rule Mappings

For each finding, generate a rule using this format:

```
### [{SEVERITY}] {Finding Title}
**Source:** {VA1/VA2/Smoke/Detection}
**What's wrong:** {One-sentence explanation of the security gap}
**Impact:** {What an attacker can exploit}

**Proposed rule ({WAF vendor}):**
```{config format}
{actual rule in vendor-native syntax}
```

**Why this helps:** {How the rule addresses the specific gap}
```

### Common Finding-to-Rule Templates

**Channel blind spot — Body:**
- Enable request body inspection
- CloudFlare: Enable WAF body parsing in zone settings; create rule matching `http.request.body.raw`
- AWS: Add `ByteMatchStatement` with `FieldToMatch: Body`, `OversizeHandling: CONTINUE`
- ModSecurity: `SecRequestBodyAccess On` + `SecRule REQUEST_BODY` patterns
- F5: ASM policy > Request Body handling > Enable request body inspection
- Akamai: App & API Protector > Inspect request body > Enable POST body scanning

**Channel blind spot — Header:**
- Enable custom header inspection rules
- CloudFlare: Create firewall rule matching on `http.request.headers["x-custom"]`
- AWS: `ByteMatchStatement` targeting `HEADER` field with relevant patterns
- ModSecurity: `SecRule REQUEST_HEADERS` with appropriate patterns
- F5: ASM > Header-based attacks > Add custom header inspection
- Akamai: Custom rule > Match condition: Request Header

**Channel blind spot — Path:**
- Add path traversal rules
- CloudFlare: `(http.request.uri.path contains "..")` block rule
- AWS: `ByteMatchStatement` with `FieldToMatch: UriPath`, pattern `..`
- ModSecurity: `SecRule REQUEST_URI "@rx \.\./"` deny
- F5: ASM > URL > Disallow path traversal patterns
- Akamai: Custom rule > Path contains `..` or encoded variants

**Channel blind spot — Query:**
- Add query parameter injection rules
- CloudFlare: `(http.request.uri.query contains "SELECT" or http.request.uri.query contains "<script")`
- AWS: `SqliMatchStatement` + `XssMatchStatement` targeting `QUERY_STRING`
- ModSecurity: Enable CRS rules 942100-942999 (SQLi) and 941100-941999 (XSS)
- F5: ASM > Parameters > Enable SQL injection and XSS detection
- Akamai: Enable SQL Injection and XSS Attack Groups

**Channel blind spot — Method:**
- Restrict HTTP methods
- CloudFlare: `(http.request.method ne "GET" and http.request.method ne "POST" and http.request.method ne "HEAD")` block
- AWS: `ByteMatchStatement` with allowed methods whitelist
- ModSecurity: `SecRule REQUEST_METHOD "!@rx ^(GET|POST|HEAD)$"` deny
- F5: ASM > Allowed Methods > restrict to GET, POST, HEAD
- Akamai: Custom rule > Deny non-standard HTTP methods

**No rate limiting (throttle = 0):**
- CloudFlare: Rate Limiting Rule — 100 requests/10 seconds per IP, action: challenge
- AWS: AWS WAF Rate-based Rule — 2000 requests/5 minutes per IP, action: block
- ModSecurity: `SecRule IP:REQUEST_COUNT "@gt 100"` with `initcol:ip=%{REMOTE_ADDR}`, `setvar:ip.request_count=+1`, `expirevar:ip.request_count=60`
- F5: ASM > DoS Protection > TPS-based detection > Set per-source thresholds
- Akamai: Rate Control > Define rate policy > 100 requests/10 seconds

**Low challenge score:**
- CloudFlare: Managed Challenge on suspicious traffic patterns; enable Under Attack Mode thresholds
- AWS: CAPTCHA action on matching WAF rules
- ModSecurity: `SecAction "phase:2,deny,status:403"` for blocked requests; integrate with CAPTCHA module
- F5: ASM > Bot Defense > Enable CAPTCHA challenges
- Akamai: Client Reputation > Enable challenge actions for suspicious clients

**High allowed rate (>30% attack probes pass):**
- Review and enable OWASP Core Rule Set (CRS)
- Enable paranoia level 2 or higher
- CloudFlare: Set WAF sensitivity to "High"; enable all managed rule groups
- AWS: Enable AWS Managed Rules — Core rule set, Known bad inputs, SQL database, Linux OS
- ModSecurity: Set `SecRule TX:PARANOIA_LEVEL "@lt 2"` to increase paranoia level
- F5: ASM > Security Policy > Increase enforcement readiness level
- Akamai: WAF Protection > Enable all attack groups > Set to Deny mode

**Detection-only mode (WAF not blocking):**
- Primary recommendation: switch from detection/monitor mode to blocking mode
- CloudFlare: Change WAF rules from "Log" to "Block"
- AWS: Change rule actions from `Count` to `Block`
- ModSecurity: Change `SecRuleEngine DetectionOnly` to `SecRuleEngine On`
- F5: ASM > Security Policy > Change enforcement mode from Transparent to Blocking
- Akamai: Change security policy actions from Alert to Deny

**Zero statefulness:**
- CloudFlare: Enable Bot Management; configure session-based rate limiting
- AWS: Enable AWS WAF Bot Control; use IP reputation lists
- ModSecurity: Enable `SecRule` collection with `initcol` for IP tracking; use persistent storage
- F5: ASM > Session Tracking > Enable session awareness; Bot Defense > Enable proactive bot defense
- Akamai: Enable Client Reputation; Bot Manager > Session-based detection

---

## Section 5 — Review Mode

When the user invokes `/waf-assess` with no target, or `/waf-assess --review`:

1. Look for a saved report at `~/.waf-detector/last-report.json`
2. If no saved report exists, check `/tmp/smoke-results.json` or ask the user for a report path
3. Parse the saved report data
4. Generate the same structured markdown report from Section 3 using the saved data
5. Propose remediation rules from Section 4 for all Critical and Medium findings
6. Skip the scan pipeline entirely — review mode is offline analysis only

If the user provides a file path (e.g., `/waf-assess /path/to/report.json`), use that file instead.

---

## Section 6 — Explanation Glossary

Use these definitions when explaining results to the user. Inline them naturally in your status updates and report narrative.

| Term | Definition |
|------|-----------|
| **WBF** (WAF Behavioral Fingerprint) | 5 signals measuring WAF sophistication: normalization, statefulness, challenge, throttle, differential |
| **PMI** (Protection Maturity Index) | Weighted composite of WBF signals on a 0-100 scale. Higher = more sophisticated WAF behavior |
| **Discrimination rate** | Percentage of paired probes where the WAF treated the attack payload differently from the benign control. 100% = perfect detection, 0% = blind spot |
| **Blind spot** | A channel (Path/Query/Header/Body/Method) where the WAF shows 0% discrimination — attacks in that channel pass undetected |
| **VA1 enforcement** | Tests whether known categorized attack payloads (SQLi, XSS, path traversal, etc.) are blocked, challenged, or allowed through the WAF |
| **VA2 behavioral profiling** | Tests WAF sophistication via 5-phase paired control probes across 5 channels, measuring behavioral patterns rather than just block rates |
| **Posture grade** | A-F letter grade computed from detection confidence + enforcement scores + behavioral profiling. A = strong, F = absent/non-functional |
| **SemanticDrift** | VA1 category: payloads modified to change meaning while preserving attack intent (e.g., synonym substitution) |
| **ProtocolMutation** | VA1 category: payloads that exploit HTTP protocol variations (e.g., method override, chunked encoding) |
| **EncodingBypass** | VA1 category: payloads using various encodings (URL, Unicode, hex, double-encoding) to bypass pattern matching |
| **StructuralAbuse** | VA1 category: payloads that abuse request structure (e.g., parameter pollution, nested contexts) |
| **Normalization signal** | WBF signal: does the WAF decode/normalize payloads before matching? High = resistant to encoding tricks |
| **Statefulness signal** | WBF signal: does the WAF track session state across requests? High = aware of multi-step attacks |
| **Challenge signal** | WBF signal: does the WAF issue challenges (CAPTCHAs, JS challenges) for suspicious traffic? |
| **Throttle signal** | WBF signal: does the WAF rate-limit or throttle high-volume request patterns? |
| **Differential signal** | WBF signal: does the WAF treat attack payloads differently from benign baseline requests? The most fundamental indicator |

---

## Important Notes

- **Consent is mandatory** for VA1, VA2, and effectiveness testing. Never skip the consent step.
- **Only test systems the user owns or has explicit permission to test.** Ask the user to confirm authorization.
- **Rate limiting is enforced** — the CLI defaults to 60 requests/minute. Do not override this without user request.
- **Rules are proposals** — always remind the user to validate rules in a staging environment before deploying to production.
- **If a step fails**, report the error clearly and ask the user whether to continue with remaining steps or abort.
- **Static content warning** — if smoke test or VA1 shows all responses are identical, the target may serve only static content. Recommend testing dynamic endpoints (login, search, API).
- **Timeout handling** — if scans are slow, note this in the report. The CLI defaults to 30s per request.
