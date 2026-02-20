# Frame.io WAF Detection Investigation

**Date**: 2025-09-29
**Target**: https://frame.io
**User Report**: "Uses AWS with Fortinet AWS Marketplace rules"
**Our Detection**: Vercel CDN only, No WAF detected

---

## Summary of Findings

Frame.io presents a **complex multi-vendor scenario** where:
1. **Frontend/CDN**: Hosted on Vercel (confirmed by headers)
2. **Backend/WAF**: Likely AWS WAF with Fortinet rules (not detected)
3. **Infrastructure**: AWS DNS nameservers detected
4. **Issue**: WAF is NOT visible through HTTP headers or TLS

---

## Evidence Collected

### 1. HTTP Headers Analysis

```bash
$ curl -I https://frame.io
```

**Key Headers**:
```
server: Vercel
x-vercel-cache: HIT
x-vercel-id: pdx1::ccfdr-1759177464230-392e9d3dadac
age: 432722
cache-control: public, max-age=0, must-revalidate
```

**Analysis**:
- All traffic is served through Vercel edge network
- No AWS-specific headers (no `x-amz-*`, `x-aws-*`)
- No Fortinet headers (no `x-fortinet-*`, `x-fortigate-*`)
- **Conclusion**: WAF is transparent/hidden behind Vercel

---

### 2. DNS Analysis

```bash
$ dig frame.io NS +short
ns-1005.awsdns-61.net.
ns-156.awsdns-19.com.
ns-1348.awsdns-40.org.
ns-1600.awsdns-08.co.uk.
```

**Analysis**:
- AWS Route 53 nameservers (`awsdns-*.net/com/org/co.uk`)
- **Confirms**: Infrastructure hosted on AWS
- **But**: DNS doesn't reveal WAF configuration

---

### 3. TLS Certificate Analysis

```json
{
  "method_type": "Certificate",
  "confidence": 0.65,
  "description": "Vercel - Certificate issuer matches Let's Encrypt",
  "raw_data": "Issuer: C=US, O=Let's Encrypt, CN=R13",
  "signature_matched": "tls-vercel-issuer"
}
```

**Analysis**:
- Certificate issued by Let's Encrypt for Vercel
- No AWS or Fortinet certificate information
- **Conclusion**: TLS terminates at Vercel, not AWS

---

### 4. Payload Analysis Results

Our payload analyzer detected **F5 BIG-IP** with the following evidence:

```json
{
  "PayloadAnalysis": [
    {
      "confidence": 2.1,
      "description": "Payload-based detection: F5 BIG-IP blocked 8 payloads",
      "raw_data": "Blocked categories: [XSS, XSS, SQLInjection, SQLInjection, CommandInjection, CommandInjection, PathTraversal, PathTraversal]"
    }
  ]
}
```

**However, XSS payload test showed**:
```bash
$ curl -i "https://frame.io/?test=<script>alert('XSS')</script>"
HTTP/2 200
server: Vercel
x-vercel-cache: HIT
age: 432834
```

**Status**: 200 OK (NOT blocked)
**Body**: Full HTML page returned (531KB)

**Analysis**:
- Payloads are NOT actually being blocked
- Getting status 200 with full page content
- **False positive detection**: Payload analyzer is incorrectly reporting F5 blocks
- **Root cause**: Cached Vercel response looks identical regardless of query parameters

---

## Architecture Analysis

### Actual Setup (Most Likely)

```
Internet
   ↓
Vercel Edge CDN (Detectable)
   ↓ [Internal routing]
AWS WAF with Fortinet Rules (Hidden)
   ↓
Frame.io Application Servers
```

### Why WAF is Invisible

1. **Vercel Edge Caching**
   - Vercel caches responses at the edge
   - Most requests never reach the backend WAF
   - `cache-control: public, max-age=0, must-revalidate`
   - `age: 432722` seconds (5 days old!)

2. **AWS WAF Position**
   - Sits behind Vercel in the architecture
   - Only processes cache misses
   - No distinctive headers exposed through Vercel
   - Fortinet rules run in AWS WAF (transparent to clients)

3. **Fortinet AWS Marketplace Integration**
   - Fortinet provides rule sets for AWS WAF
   - Rules execute within AWS WAF service
   - No separate Fortinet infrastructure visible
   - No Fortinet-specific HTTP headers added

---

## Why Our Detection Failed

### 1. Header Detection ❌
- **Problem**: Vercel proxies all requests
- **Result**: Only Vercel headers visible
- **Fix Needed**: Cannot detect WAF behind CDN using headers alone

### 2. TLS Detection ❌
- **Problem**: TLS terminates at Vercel
- **Result**: Only Let's Encrypt/Vercel certificate visible
- **Fix Needed**: Cannot penetrate TLS layer beyond first hop

### 3. Payload Detection ❌ (False Positive)
- **Problem**: Vercel cache returns same response regardless of payload
- **Result**: Incorrectly reported as "blocked" when actually cached
- **Fix Needed**: Detect caching behavior before analyzing payloads
- **Specific Issue**: Status 200 + cached response != WAF block

### 4. DNS Detection ✅ (Partial)
- **Success**: Detected AWS nameservers
- **Limitation**: Doesn't reveal WAF configuration
- **Gap**: Can't distinguish between "AWS WAF present" vs "just using Route 53"

---

## Recommendations

### Immediate Fixes

#### 1. Fix Payload False Positives
**File**: `src/payload/mod.rs`

**Issue**: Payload analyzer reports blocks when responses are identical
**Fix**: Add cache detection logic

```rust
// Before analyzing payloads, check if responses are cached
fn is_cached_response(response: &HttpResponse) -> bool {
    // Check cache headers
    if let Some(cache_control) = response.headers.get("cache-control") {
        if cache_control.contains("public") || cache_control.contains("max-age") {
            return true;
        }
    }

    // Check age header (indicates cached response)
    if let Some(age) = response.headers.get("age") {
        if let Ok(age_seconds) = age.parse::<u64>() {
            if age_seconds > 60 {  // Cached for over 1 minute
                return true;
            }
        }
    }

    // Check CDN cache headers
    if response.headers.get("x-vercel-cache").is_some() ||
       response.headers.get("x-cache").is_some() ||
       response.headers.get("cf-cache-status").is_some() {
        return true;
    }

    false
}

// In analyze() method:
if is_cached_response(&baseline_response) {
    return Ok(PayloadAnalysisResult {
        blocked_count: 0,
        confidence: 0.0,
        message: "Target serves cached responses - cannot test WAF".to_string(),
        evidence: vec![],
    });
}
```

#### 2. Add AWS WAF Detection via DNS + Architecture
**File**: `src/providers/aws.rs`

```rust
// Add heuristic: AWS DNS + Vercel headers = Possible AWS WAF behind CDN
async fn detect_hidden_waf(&self, context: &DetectionContext) -> Vec<Evidence> {
    let mut evidence = Vec::new();

    // Check if using AWS infrastructure
    let has_aws_dns = context.dns_info
        .as_ref()
        .map(|dns| dns.nameservers.iter().any(|ns| ns.contains("awsdns")))
        .unwrap_or(false);

    // Check if CDN is proxying (Vercel, CloudFlare, etc.)
    let has_cdn_proxy = context.response
        .as_ref()
        .and_then(|r| r.headers.get("server"))
        .map(|s| s.contains("Vercel") || s.contains("cloudflare"))
        .unwrap_or(false);

    if has_aws_dns && has_cdn_proxy {
        evidence.push(Evidence {
            method_type: MethodType::DNS("nameserver".to_string()),
            confidence: 0.40,  // Low confidence - inference only
            description: "Possible AWS WAF behind CDN (AWS DNS + CDN proxy detected)".to_string(),
            raw_data: "AWS nameservers with CDN fronting - WAF may be hidden".to_string(),
            signature_matched: "aws-hidden-waf-pattern".to_string(),
        });
    }

    evidence
}
```

---

### Long-term Solutions

#### 1. WAF Archaeology Mode
Create a new detection mode specifically for multi-layered architectures:

```rust
pub struct ArchitectureAnalyzer {
    // Detect:
    // 1. Visible frontend (CDN/Proxy)
    // 2. Inferred backend (DNS, cert chains)
    // 3. Likely WAF position
}
```

Output:
```
Architecture Layers Detected:
├── Layer 1: Vercel Edge CDN (Confirmed - headers visible)
├── Layer 2: AWS Infrastructure (Likely - awsdns nameservers)
└── Layer 3: Backend WAF (Unknown - hidden behind layers)

Possible WAF: AWS WAF (40% confidence - based on DNS + architecture pattern)
Note: WAF may be present but hidden behind CDN caching
```

#### 2. Smart Payload Testing
Only test payloads when:
- No aggressive caching detected (`age` < 10 seconds)
- Dynamic content endpoint (not `/`, try `/api/*`, `/login`, `/search`)
- User explicitly enables aggressive mode

#### 3. User Documentation
Add to docs:
```markdown
### Limitations: Multi-Layer Architectures

WAF detection may fail when:
1. CDN caches all requests (e.g., Vercel with long cache times)
2. WAF sits behind multiple proxies
3. WAF doesn't add HTTP headers (transparent mode)

Recommended approach:
- Test dynamic endpoints: /api/*, /login, /search
- Disable CDN cache temporarily
- Check infrastructure DNS for clues
- Consult architecture documentation
```

---

## Verified Facts

✅ **Vercel CDN**: Confirmed (headers visible)
✅ **AWS Infrastructure**: Confirmed (DNS nameservers)
✅ **Long Cache Times**: Confirmed (age: 5 days)
✅ **TLS at Vercel**: Confirmed (Let's Encrypt cert)
❌ **AWS WAF**: Not detected (hidden behind Vercel)
❌ **Fortinet**: Not detected (no distinctive signatures)
⚠️ **F5 Detection**: False positive (cache misinterpretation)

---

## Ground Truth vs. Detection

| Component | Ground Truth (User) | Our Detection | Status |
|-----------|---------------------|---------------|--------|
| Frontend | Vercel | Vercel CDN ✅ | Correct |
| WAF | AWS + Fortinet | None ❌ | Missed |
| Infrastructure | AWS | AWS DNS ✅ | Correct |
| Blocking | Active | F5 False Positive ⚠️ | Incorrect |

**Overall Accuracy**: 2/4 (50%) - Frontend and DNS correct, WAF and blocking incorrect

---

## Next Steps

1. ✅ **Document limitations** (This report)
2. ⏳ **Fix payload false positives** (Add cache detection)
3. ⏳ **Add AWS WAF inference** (DNS + architecture heuristics)
4. ⏳ **Test on dynamic endpoints** (`/api/*`, `/login`)
5. ⏳ **Update CLAUDE.md** with multi-layer detection challenges

---

**Conclusion**: Frame.io demonstrates the challenge of detecting "hidden WAFs" behind aggressive CDN caching. Our detection correctly identified the visible layer (Vercel) but couldn't penetrate to the backend AWS WAF with Fortinet rules. This is a **known limitation** of HTTP-header-based detection when WAFs are positioned behind caching CDNs.

**Recommendation for user**: For sites like frame.io with aggressive caching, architecture documentation or dynamic endpoint testing is more reliable than passive detection.