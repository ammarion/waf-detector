# WAF Detector

CLI tool for detecting, testing, and profiling Web Application Firewalls (WAFs) and Content Delivery Networks (CDNs).

> **Important:** Only test systems you own or have explicit authorization to test.

## What It Does

| Mode | What it tests | Flag |
|------|--------------|------|
| **Detection** | Identifies which WAF/CDN protects a target | `waf-detect <url>` |
| **Smoke Test** | Sends known attack payloads, measures block rates | `--smoke-test <url>` |
| **Enforcement Test** | Sends categorized attack probes, measures block/challenge/allow | `--va <url>` |
| **Behavioral Analysis** | Paired probes testing WAF sophistication across 5 channels | `--va2 <url> --va2-run` |
| **Posture Report** | Unified grade (A-F) combining all test results | `--posture <url>` |

## Quick Start

```bash
cargo build --release
./target/release/waf-detect scan example.com
```

## Commands

| Mode | Command |
|------|---------|
| **Detection** | `waf-detect scan <url>` or `waf-detect <url>` |
| **Smoke test** | `waf-detect --smoke-test <url>` |
| **Enforcement** | `waf-detect va <url>` |
| **Behavioral** | `waf-detect va2 <url> --run` |
| **Posture** | `waf-detect --posture <url>` |
| **Effectiveness** | `waf-detect --effectiveness <url>` |

## Detection

Identifies WAF/CDN via headers, body, DNS, TLS, and timing. **12 providers:** CloudFlare, AWS, Akamai, Fastly, Vercel, Azure, F5, Imperva, ModSecurity, Sucuri, Radware, FortiWeb.

```bash
waf-detect scan example.com --json
waf-detect scan @urls.txt --ndjson
```

## Output Options

- `--json` / `--ndjson` / `--compact` / `--yaml`
- `waf-detect providers` — list providers
- `waf-detect doctor` — environment health check

## Development

```bash
cargo test --lib
cargo clippy -- -D warnings
cargo fmt
```

See [DEVELOPMENT.md](DEVELOPMENT.md) for full details.

## License

MIT OR Apache-2.0
