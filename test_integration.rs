use tempfile::NamedTempFile;
use waf_detector::{
    dns::DnsAnalyzer, registry::ProviderRegistry, timing::TimingAnalyzer, DetectionContext,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    let mut temp_file = NamedTempFile::new()?;

    writeln!(temp_file, "Testing WAF Detector Integration...")?;

    // Test DNS analyzer
    writeln!(temp_file, "Testing DNS analyzer...")?;
    let dns_analyzer = DnsAnalyzer::new();
    let resolver = waf_detector::dns::optimized::DnsResolver::new()?;

    // Test multiple domains to find CNAME records
    let test_domains = vec!["www.github.com", "www.discord.com", "blog.cloudflare.com"];

    for domain in test_domains {
        writeln!(temp_file, "Testing DNS for {domain}...")?;
        let dns_info = resolver.resolve(domain).await;

        match dns_info {
            Ok(info) => {
                let evidence = dns_analyzer.analyze_from_info(&info);
                writeln!(temp_file, "  DNS evidence count: {}", evidence.len())?;
                for ev in evidence {
                    writeln!(
                        temp_file,
                        "    - DNS: {} (confidence: {:.2})",
                        ev.description, ev.confidence
                    )?;
                }
            }
            Err(e) => {
                writeln!(temp_file, "  DNS resolution failed: {e}")?;
            }
        }
    }

    // Test timing analyzer
    writeln!(temp_file, "Testing timing analyzer...")?;
    let timing_analyzer = TimingAnalyzer::new(Default::default());
    let timing_result = timing_analyzer.analyze("https://example.com").await;
    writeln!(
        temp_file,
        "Timing analysis result: {:?}",
        timing_result.is_ok()
    )?;
    if let Ok(evidence) = &timing_result {
        writeln!(temp_file, "Timing evidence count: {}", evidence.len())?;
        for ev in evidence {
            writeln!(
                temp_file,
                "  - Timing: {} (confidence: {:.2})",
                ev.description, ev.confidence
            )?;
        }
    }

    // Test registry integration
    writeln!(temp_file, "Testing registry integration...")?;
    let registry = ProviderRegistry::new();

    // Register CloudFlare provider for testing
    use waf_detector::providers::cloudflare::CloudFlareProvider;
    use waf_detector::providers::Provider;

    let cloudflare_provider = Provider::CloudFlare(CloudFlareProvider::new());
    registry.register_provider(cloudflare_provider)?;

    writeln!(
        temp_file,
        "Registered providers: {}",
        registry.get_provider_count()
    )?;

    // Test with a URL that might have CNAME records
    let context = DetectionContext {
        url: "https://www.github.com".to_string(), // www subdomain more likely to have CNAME
        response: None,
        dns_info: None,
        user_agent: "test".to_string(),
    };

    let detection_result = registry.detect_all(&context).await;
    writeln!(
        temp_file,
        "Registry detection result: {:?}",
        detection_result.is_ok()
    )?;

    if let Ok(result) = detection_result {
        writeln!(
            temp_file,
            "Evidence map keys: {:?}",
            result.evidence_map.keys().collect::<Vec<_>>()
        )?;
        writeln!(temp_file, "Detection time: {}ms", result.detection_time_ms)?;
        writeln!(temp_file, "WAF detected: {:?}", result.detected_waf)?;
        writeln!(temp_file, "CDN detected: {:?}", result.detected_cdn)?;

        for (provider, evidence_list) in &result.evidence_map {
            if !evidence_list.is_empty() {
                writeln!(
                    temp_file,
                    "Provider {}: {} evidence items",
                    provider,
                    evidence_list.len()
                )?;
                for evidence in evidence_list {
                    writeln!(
                        temp_file,
                        "  - {} (method: {:?}, confidence: {:.2})",
                        evidence.description, evidence.method_type, evidence.confidence
                    )?;
                }
            }
        }

        // Test JSON serialization (what the web API would return)
        let json_result = serde_json::to_string_pretty(&result)?;
        writeln!(temp_file, "\nJSON representation (first 500 chars):")?;
        writeln!(temp_file, "{}", &json_result[..json_result.len().min(500)])?;
    }

    writeln!(temp_file, "Integration test completed!")?;
    temp_file.flush()?;

    println!(
        "Test completed! Temp output at: {:?} (will be deleted)",
        temp_file.path()
    );
    Ok(())
}
