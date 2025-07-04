# Detection Techniques Task Tracker

This document tracks the progress of Detection Techniques (Section 11) and the prerequisite WAF smoke test porting. Each task includes its rationale, status, dependencies, and detailed subtasks. **Between each major task, we must validate that everything works end-to-end (CLI, API, UI).**

---

## Task List

### 0. Port WAF Smoke Testing Bash Script to Rust
- [x] Analyze current bash script functionality and dependencies (DONE)
- [x] Design Rust CLI interface:
    - [x] Parse URL argument (with or without FUZZ)
    - [x] Support -o <output.json> for JSON output
    - [x] Support -H "Header: Value" (repeatable)
- [x] Implement payload and category management (8+ attack types with advanced payloads)
- [x] Implement URL manipulation (insert/append FUZZ as needed)
- [x] Implement HTTP requests:
    - [x] Send requests with timeout (10s)
    - [x] Support custom headers
    - [x] Small delay between requests (0.1s)
- [x] Implement response classification:
    - [x] BLOCKED (403/406/429/503)
    - [x] ALLOWED (200/301/302)
    - [x] ERROR (other)
    - [x] RATE_LIMITED (429)
    - [x] CHALLENGE (captcha/challenge pages)
- [x] Implement terminal output:
    - [x] Print colored results for each payload with emojis
    - [x] Print comprehensive summary table with effectiveness %
    - [x] Real-time progress display
- [x] Implement JSON output (if -o is set):
    - [x] Write detailed summary and per-payload results to file
    - [x] Include WAF mode, detected WAF, recommendations
- [x] Effectiveness calculation (blocked/total)
- [x] Add unit tests for core logic
- [x] Integrate with main Rust codebase
- [ ] Validate from CLI (run smoke tests via CLI)
- [ ] Validate via API (expose smoke test endpoint if needed)
- [ ] Validate via UI (if applicable)
- [ ] Update documentation and this file

**IMPROVEMENTS OVER BASH SCRIPT:**
- 🎯 **Better Detection**: Advanced payloads, WAF mode detection, specific WAF identification
- 🌈 **Colorful Output**: Real-time colored results with emojis and comprehensive tables
- 📊 **Rich Analysis**: Effectiveness percentage, response time analysis, recommendations
- 🔧 **More Options**: Aggressive mode, custom headers, detailed JSON export
- 🛡️ **Security**: Better error handling, rate limiting awareness, challenge detection

### 11.1 Enhance WAF Mode Detection with Timing Analysis & Active Probing
- [ ] Design timing analysis and active probing logic
- [ ] Implement timing analysis in detection engine
- [ ] Implement active probing techniques
- [ ] Add unit and integration tests
- [ ] Validate from CLI (detection results)
- [ ] Validate via API (detection endpoint)
- [ ] Validate via UI (detection feedback)
- [ ] Update documentation and this file

### 11.2 Implement Token Bucket Rate Limiting (Burst, Fingerprint-based)
- [ ] Design rate limiting strategy (token bucket, burst, fingerprint-based)
- [ ] Implement rate limiting in backend
- [ ] Add configuration options
- [ ] Add unit and integration tests
- [ ] Validate from CLI (rate limit triggers)
- [ ] Validate via API (rate limit enforcement)
- [ ] Validate via UI (user feedback/errors)
- [ ] Update documentation and this file

### 11.3 Implement Security Module (Fingerprint Hashing, Consent, API Keys)
- [ ] Design security module (fingerprint hashing, consent management, anti-fingerprinting, API key protection)
- [ ] Implement fingerprint hashing
- [ ] Implement consent management UI/API
- [ ] Implement anti-fingerprinting detection
- [ ] Implement API key protection
- [ ] Add unit and integration tests
- [ ] Validate from CLI (security features)
- [ ] Validate via API (security endpoints)
- [ ] Validate via UI (consent, errors, key management)
- [ ] Update documentation and this file

### 11.4 Create ActiveProbing Module (3-phase Detection: Normal, Malicious Payload, Pattern Analysis)
- [ ] Design 3-phase detection logic
- [ ] Implement normal probing
- [ ] Implement malicious payload probing
- [ ] Implement pattern analysis
- [ ] Add unit and integration tests
- [ ] Validate from CLI (all phases)
- [ ] Validate via API (detection endpoint)
- [ ] Validate via UI (detection feedback)
- [ ] Update documentation and this file

### 11.5 Implement JA3/JA4 TLS Fingerprinting for Infrastructure Detection
- [ ] Research and design JA3/JA4 integration
- [ ] Implement TLS fingerprinting logic
- [ ] Integrate with detection engine
- [ ] Add unit and integration tests
- [ ] Validate from CLI (TLS fingerprinting results)
- [ ] Validate via API (detection endpoint)
- [ ] Validate via UI (detection feedback)
- [ ] Update documentation and this file

### 11.6 Create Configurable Detection Intensity Modes
- [ ] Design detection intensity modes (speed vs accuracy)
- [ ] Implement mode selection in backend
- [ ] Add configuration options (CLI, API, UI)
- [ ] Add unit and integration tests
- [ ] Validate from CLI (mode selection)
- [ ] Validate via API (mode selection)
- [ ] Validate via UI (mode selection and feedback)
- [ ] Update documentation and this file

---

## Validation Between Tasks
- [ ] After each major task, perform end-to-end validation:
    - [ ] CLI: All new/changed features work as expected
    - [ ] API: Endpoints behave correctly, including error handling
    - [ ] UI: User experience is correct, errors and feedback are clear
    - [ ] Regression: No existing features are broken
    - [ ] Update this file with results and check off completed items

---

## Status Legend
- [ ] Pending
- [x] Completed

**Always reference and update this file as you work through tasks.** 