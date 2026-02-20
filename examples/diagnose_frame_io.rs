use waf_detector::{http::HttpClient, providers::aws::AwsProvider, DetectionProvider};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Diagnosing frame.io for AWS CloudFront detection...");

    let client = HttpClient::new()?;
    let provider = AwsProvider::new();

    // Test frame.io
    println!("\n📡 Fetching frame.io response...");
    let response = client.get("https://frame.io").await?;

    println!("\n{}", provider.diagnose_response(&response));

    // Test actual detection
    println!("\n=== Detection Results ===");
    let evidence = provider.passive_detect(&response).await?;

    if evidence.is_empty() {
        println!("❌ No AWS/CloudFront detected");
    } else {
        println!(
            "✅ AWS/CloudFront detected with {} pieces of evidence:",
            evidence.len()
        );
        for (i, ev) in evidence.iter().enumerate() {
            println!(
                "  {}. {} - {} (confidence: {:.1}%)",
                i + 1,
                ev.description,
                ev.raw_data,
                ev.confidence * 100.0
            );
        }
    }

    Ok(())
}
