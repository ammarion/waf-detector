---
name: test-dashboard
description: Browser-test the WAF detector dashboard with Playwright
user_invocable: true
---

# Dashboard Test Skill

Launch the web server and validate the dashboard UI using Playwright browser automation.

## Prerequisites

- Build first: `cargo build --release`
- Kill any existing server: `pkill -f 'waf-detect.*--web'`

## Steps

1. Start server: `./target/release/waf-detect --web --port 8080 &`
2. Wait for healthy: `curl -s http://localhost:8080/api/status`
3. Navigate to `http://localhost:8080`

### Test checklist

- [ ] **Detect tab**: Single URL scan — enter `https://cloudflare.com`, click Scan, verify CloudFlare detected
- [ ] **Evidence**: Click "View Evidence" — verify items expand/collapse, no `Some(...)` or `None` in data
- [ ] **Batch scan**: Enter 2 URLs, click Scan Batch, verify both results appear
- [ ] **Test tab**: WAF Smoke Test, Virtual Adversary, Advanced Security Profiling sections visible
- [ ] **Reports tab**: Quick Actions, Consent Status, VA History sections visible
- [ ] **Export JSON**: Click Export JSON with results present — verify download triggers
- [ ] **Console errors**: Check `browser_console_messages` — must be 0 errors
- [ ] **Responsive**: Resize to 390px (mobile), 768px (tablet), 1440px (desktop) — verify layout adapts

## Cleanup

Kill the server after testing: `pkill -f 'waf-detect.*--web'`
