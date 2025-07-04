# Manual UI Testing Guide

## Prerequisites
- Web server running: `cargo run --bin waf-detect -- --web --port 8080`
- Browser (Chrome, Firefox, Safari)
- Internet connection for testing external URLs

## Test Suite Overview

### 1. Basic Interface Testing

#### 1.1 Dashboard Access
- **URL**: http://localhost:8080/
- **Expected**: WAF Detector dashboard loads
- **Check**:
  - [ ] Page title contains "WAF Detector"
  - [ ] URL input field is present
  - [ ] Scan/Detect button is visible
  - [ ] Results area is present
  - [ ] CSS styling is applied correctly
  - [ ] No JavaScript errors in console (F12)

#### 1.2 API Documentation
- **URL**: http://localhost:8080/api-docs
- **Expected**: API documentation page
- **Check**:
  - [ ] Documentation content loads
  - [ ] API endpoints are listed
  - [ ] Example requests/responses shown

### 2. Functional Testing

#### 2.1 Single URL Scan Tests

**Test Case 1: CloudFlare Detection**
- **URL**: https://cloudflare.com
- **Expected Results**:
  - [ ] WAF: CloudFlare detected
  - [ ] CDN: CloudFlare detected  
  - [ ] Confidence: >80%
  - [ ] Evidence includes headers (CF-Ray, Server)
  - [ ] ⏱️ Timing analysis indicator (orange)
  - [ ] 🌐 DNS analysis indicator (green) 
  - [ ] Evidence breakdown shows multiple categories

**Test Case 2: AWS Detection**
- **URL**: https://aws.amazon.com
- **Expected Results**:
  - [ ] CDN: AWS CloudFront detected
  - [ ] Confidence: >70%
  - [ ] Evidence includes CloudFront headers
  - [ ] DNS analysis may show cloudfront.net CNAME

**Test Case 3: GitHub (Fastly)**
- **URL**: https://github.com
- **Expected Results**:
  - [ ] CDN: Fastly detected
  - [ ] Evidence includes Fastly headers
  - [ ] DNS analysis may show fastly.com CNAME

**Test Case 4: No Detection**
- **URL**: https://example.com
- **Expected Results**:
  - [ ] WAF: Not detected
  - [ ] CDN: Not detected
  - [ ] Minimal evidence
  - [ ] Clear "not detected" message

#### 2.2 Evidence Analysis Testing

For each positive detection, verify:
- [ ] Evidence categories displayed:
  - 🛡️ **Headers** (high confidence)
  - ⏱️ **Timing** (medium confidence, orange highlight)
  - 🌐 **DNS** (high confidence, green highlight)
  - 📄 **Body** (lower confidence)
- [ ] Confidence badges with color coding:
  - 🟢 **High** (>80%)
  - 🟡 **Medium** (50-80%)
  - 🔴 **Low** (<50%)
- [ ] Evidence descriptions are clear
- [ ] Raw data snippets shown where relevant

#### 2.3 Timing Analysis Verification

**Test Process**:
1. Scan a known WAF site (e.g., cloudflare.com)
2. Check for timing evidence
3. **Expected**:
   - [ ] ⏱️ Timing evidence indicator appears
   - [ ] Orange highlighting for timing evidence
   - [ ] Description mentions processing delay (e.g., "96ms delay")
   - [ ] Confidence score for timing evidence (typically 40-60%)

#### 2.4 DNS Analysis Verification

**Test Process**:
1. Scan a CDN site (e.g., github.com, cloudflare.com)
2. Check for DNS evidence
3. **Expected**:
   - [ ] 🌐 DNS evidence indicator appears
   - [ ] Green highlighting for DNS evidence
   - [ ] Shows CNAME record details
   - [ ] High confidence score (98-99%)
   - [ ] Description mentions "Infrastructure-level detection"

### 3. User Experience Testing

#### 3.1 Loading States
- [ ] Scan button shows loading state during request
- [ ] Progress indication during scan
- [ ] Appropriate timeouts (30s max)
- [ ] Error handling for network issues

#### 3.2 Visual Design
- [ ] Responsive design works on different screen sizes
- [ ] Colors and icons are consistent
- [ ] Text is readable and well-formatted
- [ ] Evidence categories are visually distinct:
  - Orange for timing
  - Green for DNS
  - Default styling for headers/body

#### 3.3 Error Handling
**Invalid URL Test**:
- **Input**: `invalid-url`
- **Expected**: Clear error message

**Timeout Test**:
- **Input**: URL with very slow response
- **Expected**: Graceful timeout handling

**Server Error Test**:
- Stop the server temporarily
- **Expected**: Connection error message

### 4. API Testing (Optional)

#### 4.1 Direct API Calls
Using browser dev tools or curl:

**Health Check**:
```bash
curl http://localhost:8080/api/status
```
**Expected**: `{"success":true,"status":"healthy",...}`

**Scan Request**:
```bash
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://cloudflare.com"}'
```

#### 4.2 Providers List
```bash
curl http://localhost:8080/api/providers
```
**Expected**: List of available providers

### 5. Performance Testing

#### 5.1 Response Times
- [ ] Dashboard loads in <2s
- [ ] Scan requests complete in <30s
- [ ] No memory leaks during extended use

#### 5.2 Concurrent Requests
- [ ] Multiple tabs can scan simultaneously
- [ ] Server handles concurrent requests

### 6. Cross-Browser Testing

Test in multiple browsers:
- [ ] Chrome
- [ ] Firefox  
- [ ] Safari
- [ ] Edge

## Test Results Documentation

### Test Environment
- **Date**: ___________
- **Server Version**: 1.0.0
- **Browser**: ___________
- **OS**: ___________

### Results Summary
- **Total Tests**: ___/___
- **Passed**: ___
- **Failed**: ___
- **Success Rate**: ___%

### Issues Found
| Test Case | Issue | Severity | Notes |
|-----------|-------|----------|-------|
|           |       |          |       |

### Recommendations
- [ ] UI improvements needed
- [ ] Functional fixes required
- [ ] Performance optimizations
- [ ] Additional features

## Automation Checklist

After manual testing, consider automating:
- [ ] Health check monitoring
- [ ] Basic scan functionality
- [ ] Evidence type verification
- [ ] Performance benchmarks

## Next Steps

1. Complete manual testing
2. Document any issues
3. Implement fixes
4. Proceed to next development phase
5. Repeat testing after each feature addition 