---
name: waf-assess
description: Run comprehensive WAF security assessments, analyze results, and propose vendor-specific remediation rules
user_invocable: true
---

# Claude wrapper for the shared WAF assessment workflow.

Source of truth: `agent-skills/waf-assess/WORKFLOW.md`

Read the shared workflow before taking action.
If this wrapper and the shared workflow disagree, follow the shared workflow and update the wrapper in the same change.
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
