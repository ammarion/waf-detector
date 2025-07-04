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

