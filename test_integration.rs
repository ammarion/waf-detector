use waf_detector::{
    registry::ProviderRegistry,
    DetectionContext,
    dns::DnsAnalyzer,
    timing::TimingAnalyzer,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::File;
    use std::io::Write;
    
    let mut output = File::create("test_results.txt")?;
    
    writeln!(output, "Testing WAF Detector Integration...")?;
    
    // Test DNS analyzer
    writeln!(output, "Testing DNS analyzer...")?;
    let dns_analyzer = DnsAnalyzer::new();
    
    // Test multiple domains to find CNAME records
    let test_domains = vec!["www.github.com", "www.discord.com", "blog.cloudflare.com"];
    
    for domain in test_domains {
        writeln!(output, "Testing DNS for {}...", domain)?;
        let dns_result = dns_analyzer.analyze(domain).await;
        writeln!(output, "  DNS analysis result: {:?}", dns_result.is_ok())?;
        if let Ok(evidence) = &dns_result {
            writeln!(output, "  DNS evidence count: {}", evidence.len())?;
            for ev in evidence {
                writeln!(output, "    - DNS: {} (confidence: {:.2})", ev.description, ev.confidence)?;
            }
        }
    }
    
    // Test timing analyzer
    writeln!(output, "Testing timing analyzer...")?;
    let timing_analyzer = TimingAnalyzer::new(Default::default());
    let timing_result = timing_analyzer.analyze("https://example.com").await;
    writeln!(output, "Timing analysis result: {:?}", timing_result.is_ok())?;
    if let Ok(evidence) = &timing_result {
        writeln!(output, "Timing evidence count: {}", evidence.len())?;
        for ev in evidence {
            writeln!(output, "  - Timing: {} (confidence: {:.2})", ev.description, ev.confidence)?;
        }
    }
    
    // Test registry integration
    writeln!(output, "Testing registry integration...")?;
    let registry = ProviderRegistry::new();
    
    // Register CloudFlare provider for testing
    use waf_detector::providers::cloudflare::CloudFlareProvider;
    use waf_detector::providers::Provider;
    
    let cloudflare_provider = Provider::CloudFlare(CloudFlareProvider::new());
    registry.register_provider(cloudflare_provider)?;
    
    writeln!(output, "Registered providers: {}", registry.get_provider_count())?;
    
    // Test with a URL that might have CNAME records
    let context = DetectionContext {
        url: "https://www.github.com".to_string(), // www subdomain more likely to have CNAME
        response: None,
        dns_info: None,
        user_agent: "test".to_string(),
    };
    
    let detection_result = registry.detect_all(&context).await;
    writeln!(output, "Registry detection result: {:?}", detection_result.is_ok())?;
    
    if let Ok(result) = detection_result {
        writeln!(output, "Evidence map keys: {:?}", result.evidence_map.keys().collect::<Vec<_>>())?;
        writeln!(output, "Detection time: {}ms", result.detection_time_ms)?;
        writeln!(output, "WAF detected: {:?}", result.detected_waf)?;
        writeln!(output, "CDN detected: {:?}", result.detected_cdn)?;
        
        for (provider, evidence_list) in &result.evidence_map {
            if !evidence_list.is_empty() {
                writeln!(output, "Provider {}: {} evidence items", provider, evidence_list.len())?;
                for evidence in evidence_list {
                    writeln!(output, "  - {} (method: {:?}, confidence: {:.2})", 
                           evidence.description, evidence.method_type, evidence.confidence)?;
                }
            }
        }
        
        // Test JSON serialization (what the web API would return)
        let json_result = serde_json::to_string_pretty(&result)?;
        writeln!(output, "\nJSON representation (first 500 chars):")?;
        writeln!(output, "{}", &json_result[..json_result.len().min(500)])?;
    }
    
    writeln!(output, "Integration test completed!")?;
    output.flush()?;
    
    println!("Test completed! Check test_results.txt for output.");
    Ok(())
} 