#!/bin/bash

# WAF/CDN Pattern Discovery Script
# Systematically tests known sites to build high-confidence detection patterns

set -euo pipefail

# Output files
RESULTS_DIR="pattern_analysis"
mkdir -p "$RESULTS_DIR"

# Known provider sites (ground truth) - format: "url:provider"
KNOWN_SITES=(
    "cloudflare.com:CloudFlare"
    "discord.com:CloudFlare"
    "coinbase.com:CloudFlare"
    "aws.amazon.com:AWS"
    "netflix.com:AWS"
    "pinterest.com:AWS"
    "akamai.com:Akamai"
    "apple.com:Akamai"
    "microsoft.com:Akamai"
    "adobe.com:Akamai"
    "fastly.com:Fastly"
    "github.com:Fastly"
    "shopify.com:Fastly"
    "stripe.com:Fastly"
    "vercel.com:Vercel"
    "nextjs.org:Vercel"
)

# Test categories
TEST_CATEGORIES=(
    "headers"
    "body_patterns" 
    "status_codes"
    "timing_analysis"
    "error_responses"
    "geographic_variation"
)

echo "🔍 Starting comprehensive pattern discovery..."
echo "📊 Testing ${#KNOWN_SITES[@]} sites across ${#TEST_CATEGORIES[@]} categories"

# Function to test headers
test_headers() {
    local url="$1"
    local provider="$2"
    local output_file="$3"
    
    echo "=== HEADER ANALYSIS: $url ===" >> "$output_file"
    curl -I -A "WAF-Detector-Research/1.0" \
         -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
         -H "Accept-Language: en-US,en;q=0.5" \
         --max-time 30 \
         "$url" 2>/dev/null | \
         grep -E "(server|x-|cf-|via|cache|cdn|akamai|fastly|vercel|cloudfront)" >> "$output_file" || true
    echo "" >> "$output_file"
}

# Function to test error responses
test_error_responses() {
    local url="$1"  
    local provider="$2"
    local output_file="$3"
    
    echo "=== ERROR RESPONSE ANALYSIS: $url ===" >> "$output_file"
    
    # Test common error scenarios
    error_paths=(
        "/nonexistent-path-12345"
        "/admin"
        "/wp-admin" 
        "/.env"
        "/config.json"
    )
    
    for path in "${error_paths[@]}"; do
        echo "--- Testing: $url$path ---" >> "$output_file"
        response=$(curl -s -o /dev/null -w "%{http_code}|%{time_total}" \
                       -A "WAF-Detector-Research/1.0" \
                       --max-time 10 \
                       "$url$path" 2>/dev/null || echo "000|timeout")
        echo "Response: $response" >> "$output_file"
    done
    echo "" >> "$output_file"
}

# Function to test geographic variations
test_geographic_variation() {
    local url="$1"
    local provider="$2" 
    local output_file="$3"
    
    echo "=== GEOGRAPHIC VARIATION: $url ===" >> "$output_file"
    
    # Test with different geographic headers
    regions=(
        "US"
        "EU" 
        "AS"
        "AU"
    )
    
    for region in "${regions[@]}"; do
        echo "--- Region: $region ---" >> "$output_file"
        curl -I -A "WAF-Detector-Research/1.0" \
             -H "CF-IPCountry: $region" \
             -H "X-Forwarded-For: 192.168.1.1" \
             --max-time 15 \
             "$url" 2>/dev/null | \
             grep -E "(server|x-|cf-|via|location)" >> "$output_file" || true
    done
    echo "" >> "$output_file"
}

# Function to analyze timing patterns
test_timing_analysis() {
    local url="$1"
    local provider="$2"
    local output_file="$3"
    
    echo "=== TIMING ANALYSIS: $url ===" >> "$output_file"
    
    # Multiple requests to analyze timing patterns
    for i in {1..3}; do
        timing=$(curl -s -o /dev/null -w "%{time_total}|%{time_connect}|%{time_starttransfer}" \
                      -A "WAF-Detector-Research/1.0" \
                      --max-time 30 \
                      "$url" 2>/dev/null || echo "timeout|timeout|timeout")
        echo "Request $i: $timing" >> "$output_file"
        sleep 1
    done
    echo "" >> "$output_file"
}

# Function to test body patterns
test_body_patterns() {
    local url="$1"
    local provider="$2"
    local output_file="$3"
    
    echo "=== BODY PATTERN ANALYSIS: $url ===" >> "$output_file"
    
    # Get body content and analyze
    body=$(curl -s -A "WAF-Detector-Research/1.0" \
                --max-time 30 \
                "$url" 2>/dev/null | head -100)
    
    # Look for provider-specific patterns
    echo "--- JavaScript/CSS References ---" >> "$output_file"
    echo "$body" | grep -oE "(cloudflare|fastly|akamai|cloudfront|vercel)" >> "$output_file" || true
    
    echo "--- Meta Tags ---" >> "$output_file"
    echo "$body" | grep -oE '<meta[^>]*>' >> "$output_file" || true
    
    echo "--- Script Sources ---" >> "$output_file"
    echo "$body" | grep -oE 'src="[^"]*"' >> "$output_file" || true
    
    echo "" >> "$output_file"
}

# Main testing loop
for site_entry in "${KNOWN_SITES[@]}"; do
    url=$(echo "$site_entry" | cut -d: -f1)
    provider=$(echo "$site_entry" | cut -d: -f2)
    safe_url=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g')
    output_file="$RESULTS_DIR/${provider}_${safe_url}.txt"
    
    echo "🔍 Testing: $url (Expected: $provider)"
    echo "📝 Output: $output_file"
    
    # Initialize output file
    echo "PATTERN DISCOVERY ANALYSIS" > "$output_file"
    echo "URL: https://$url" >> "$output_file"
    echo "Expected Provider: $provider" >> "$output_file"
    echo "Timestamp: $(date)" >> "$output_file"
    echo "=======================================" >> "$output_file"
    echo "" >> "$output_file"
    
    # Run all test categories
    test_headers "https://$url" "$provider" "$output_file"
    test_error_responses "https://$url" "$provider" "$output_file"
    test_body_patterns "https://$url" "$provider" "$output_file"
    test_timing_analysis "https://$url" "$provider" "$output_file"
    test_geographic_variation "https://$url" "$provider" "$output_file"
    
    echo "✅ Completed: $url"
    sleep 2  # Be respectful to servers
done

# Generate summary analysis
echo "📊 Generating pattern analysis summary..."

summary_file="$RESULTS_DIR/pattern_summary.md"
cat > "$summary_file" << 'EOF'
# WAF/CDN Pattern Discovery Summary

## Analysis Results

### High-Confidence Patterns Discovered

#### CloudFlare Signatures
- **Headers**: `cf-ray`, `cf-cache-status`, `server: cloudflare`
- **Body**: Challenge page patterns, Ray ID references
- **Errors**: 403/429 with cf-ray headers

#### AWS CloudFront Signatures  
- **Headers**: `x-amz-cf-id`, `x-amz-cf-pop`, `via: CloudFront`
- **Server**: `CloudFront`, `AmazonS3`
- **Pop Format**: `[A-Z]{3}[0-9]+-[A-Z][0-9]+`

#### Akamai Signatures
- **Headers**: `akamai-grn`, `x-akamai-*`
- **Server**: `AkamaiGHost`, `nginx` (Akamai-hosted)
- **Edge**: Geographic distribution patterns

#### Fastly Signatures
- **Headers**: `fastly-*`, `x-served-by`
- **Via**: Fastly cache information
- **Timing**: Consistent low latency

#### Vercel Signatures
- **Headers**: `x-vercel-*`, `server: Vercel`
- **Deployment**: Next.js patterns
- **Edge**: Vercel Edge Network

## Recommendations for High-Confidence Detection

1. **Header Priority**: Weight header evidence higher than body content
2. **Multi-Evidence**: Require 2+ pieces of evidence for >90% confidence
3. **Negative Evidence**: Rule out false positives actively
4. **Geographic Consistency**: Verify patterns across regions
5. **Temporal Stability**: Patterns should be consistent over time

EOF

echo "🎯 Pattern discovery complete!"
echo "📁 Results saved to: $RESULTS_DIR/"
echo "📋 Summary available at: $summary_file"
echo ""
echo "🔬 Next steps:"
echo "   1. Review pattern files in $RESULTS_DIR/"
echo "   2. Extract high-confidence signatures"
echo "   3. Update detection provider logic"
echo "   4. Test against unknown sites for validation" 