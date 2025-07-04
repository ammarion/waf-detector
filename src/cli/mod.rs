//! Simple CLI Interface - Modern and intuitive WAF detection

use crate::engine::DetectionEngine;
use crate::providers::{Provider, cloudflare::CloudFlareProvider, akamai::AkamaiProvider, aws::AwsProvider, fastly::FastlyProvider, vercel::VercelProvider};
use crate::registry::ProviderRegistry;
use crate::payload::waf_smoke_test::{WafSmokeTest, SmokeTestConfig};
use crate::DetectionResult;
use anyhow::{Result, anyhow};
use clap::{Arg, ArgMatches, Command};
use std::time::Instant;
use std::fs;
use std::collections::HashMap;
use url::Url;

pub struct SimpleCliApp {
    engine: DetectionEngine,
}

impl SimpleCliApp {
    pub async fn new() -> Result<Self> {
        let registry = ProviderRegistry::new();
        
        // Register providers
        registry.register_provider(Provider::CloudFlare(CloudFlareProvider::new()))?;
        registry.register_provider(Provider::Akamai(AkamaiProvider::new()))?;
        registry.register_provider(Provider::AWS(AwsProvider::new()))?;
        registry.register_provider(Provider::Fastly(FastlyProvider::new()))?;
        registry.register_provider(Provider::Vercel(VercelProvider::new()))?;
        
        let engine = DetectionEngine::new(registry)
            .with_waf_mode_detection();

        Ok(Self { engine })
    }

    pub async fn run(&self) -> Result<()> {
        let matches = build_simple_cli().get_matches();
        
        // Handle special commands first
        if matches.get_flag("web") {
            let port = matches.get_one::<u16>("port").copied().unwrap_or(8080);
            return self.start_web_server(port).await;
        }
        
        if matches.get_flag("list") {
            return self.list_providers().await;
        }

        // Handle smoke test command
        if matches.get_flag("smoke-test") {
            return self.run_smoke_test(&matches).await;
        }

        // Get targets to scan
        let targets = self.parse_targets(&matches)?;
        
        if targets.is_empty() {
            println!("❌ No targets specified. Use --help for usage.");
            return Ok(());
        }

        // Determine output format
        let format = self.determine_format(&matches);
        let debug = matches.get_flag("debug");
        let verbose = matches.get_flag("verbose");

        // Scan targets
        if targets.len() == 1 {
            self.scan_single(&targets[0], &format, debug, verbose).await
        } else {
            self.scan_batch(&targets, &format, debug, verbose).await
        }
    }

    fn parse_targets(&self, matches: &ArgMatches) -> Result<Vec<String>> {
        let mut targets = Vec::new();

        // Get targets from direct arguments
        if let Some(domains) = matches.get_many::<String>("targets") {
            for domain in domains {
                if domain.starts_with('@') {
                    // File input: @file.txt
                    let filename = &domain[1..];
                    let content = fs::read_to_string(filename)
                        .map_err(|e| anyhow!("Failed to read file '{}': {}", filename, e))?;
                    
                    for line in content.lines() {
                        let line = line.trim();
                        if !line.is_empty() && !line.starts_with('#') {
                            targets.push(self.normalize_url(line)?);
                        }
                    }
                } else {
                    // Direct domain/URL
                    targets.push(self.normalize_url(domain)?);
                }
            }
        }

        Ok(targets)
    }

    fn normalize_url(&self, input: &str) -> Result<String> {
        // If it's already a valid URL, use it
        if let Ok(url) = Url::parse(input) {
            return Ok(url.to_string());
        }

        // Try adding https://
        let with_https = format!("https://{}", input);
        if let Ok(url) = Url::parse(&with_https) {
            return Ok(url.to_string());
        }

        Err(anyhow!("Invalid URL or domain: {}", input))
    }

    fn determine_format(&self, matches: &ArgMatches) -> String {
        if matches.get_flag("json") {
            "json".to_string()
        } else if matches.get_flag("yaml") {
            "yaml".to_string()
        } else if matches.get_flag("compact") {
            "compact".to_string()
        } else {
            "table".to_string()
        }
    }

    async fn scan_single(&self, url: &str, format: &str, debug: bool, verbose: bool) -> Result<()> {
        if verbose {
            println!("🔍 Scanning: {}", url);
        }

        let start_time = Instant::now();
        let detection_result = self.engine.detect(url).await?;
        let scan_time = start_time.elapsed();

        match format {
            "json" => {
                println!("{}", serde_json::to_string_pretty(&detection_result)?);
            }
            "yaml" => {
                println!("{}", serde_yaml::to_string(&detection_result)?);
            }
            "compact" => {
                self.print_compact(&detection_result);
            }
            _ => {
                self.print_table_format(&detection_result, debug);
            }
        }

        if verbose {
            println!("⏱️  Scan completed in {:.2}ms", scan_time.as_millis());
        }

        Ok(())
    }

    async fn scan_batch(&self, urls: &[String], format: &str, debug: bool, verbose: bool) -> Result<()> {
        if verbose {
            println!("🔍 Scanning {} targets...", urls.len());
        }

        let total_start = Instant::now();
        
        // Use parallel batch detection with rate limiting (max 3 concurrent requests)
        let url_refs: Vec<&str> = urls.iter().map(|s| s.as_str()).collect();
        let batch_results = self.engine.detect_batch(&url_refs, 3).await?;
        
        // Convert HashMap results back to Vec in original order for consistent output
        let mut results = Vec::new();
        for (i, url) in urls.iter().enumerate() {
            if verbose {
                println!("({}/{}) {} - Processing...", i + 1, urls.len(), url);
            }
            
            if let Some(result) = batch_results.get(url) {
                results.push(result.clone());
            }
        }

        let total_time = total_start.elapsed();

        match format {
            "json" => {
                println!("{}", serde_json::to_string_pretty(&results)?);
            }
            "yaml" => {
                println!("{}", serde_yaml::to_string(&results)?);
            }
            "compact" => {
                for result in &results {
                    self.print_compact(result);
                }
            }
            _ => {
                for (i, result) in results.iter().enumerate() {
                    if i > 0 {
                        println!();
                    }
                    self.print_table_format(result, debug);
                }
            }
        }

        if verbose {
            println!("\n⏱️  Total scan time: {:.2}s", total_time.as_secs_f64());
        }

        Ok(())
    }

    fn print_compact(&self, result: &DetectionResult) {
        let url_short = if result.url.len() > 40 {
            format!("{}...", &result.url[..37])
        } else {
            result.url.clone()
        };

        match (&result.detected_waf, &result.detected_cdn) {
            (Some(waf), Some(cdn)) if waf.name == cdn.name => {
                println!("{:<40} {} ({:.1}%)", url_short, waf.name, waf.confidence * 100.0);
            }
            (Some(waf), Some(cdn)) => {
                println!("{:<40} WAF: {}, CDN: {} ({:.1}%/{:.1}%)", 
                        url_short, waf.name, cdn.name, waf.confidence * 100.0, cdn.confidence * 100.0);
            }
            (Some(waf), None) => {
                println!("{:<40} WAF: {} ({:.1}%)", url_short, waf.name, waf.confidence * 100.0);
            }
            (None, Some(cdn)) => {
                println!("{:<40} CDN: {} ({:.1}%)", url_short, cdn.name, cdn.confidence * 100.0);
            }
            (None, None) => {
                println!("{:<40} Not Detected", url_short);
            }
        }
    }

    fn print_table_format(&self, result: &DetectionResult, debug: bool) {
        if debug {
            self.print_debug_info(result);
        }

        // Clean table format (reuse from existing CLI)
        println!("┌─────────────────────────────────────────────────────────────────────────┐");
        println!("│                            WAF/CDN Detection Results                    │");
        println!("├─────────────────────────────────────────────────────────────────────────┤");
        
        // URL (truncate if too long)
        let url_display = if result.url.len() > 67 {
            format!("{}...", &result.url[..64])
        } else {
            result.url.clone()
        };
        println!("│ URL: {:<67} │", url_display);
        println!("├─────────────────────────────────────────────────────────────────────────┤");
        
        // WAF Detection
        if let Some(waf_detection) = &result.detected_waf {
            println!("│ WAF: {:<20} Confidence: {:<6.1}%                    │", 
                    waf_detection.name, waf_detection.confidence * 100.0);
        } else {
            println!("│ WAF: Not Detected                                                      │");
        }
        
        // CDN Detection
        if let Some(cdn_detection) = &result.detected_cdn {
            println!("│ CDN: {:<20} Confidence: {:<6.1}%                    │", 
                    cdn_detection.name, cdn_detection.confidence * 100.0);
        } else {
            println!("│ CDN: Not Detected                                                      │");
        }
        
        println!("├─────────────────────────────────────────────────────────────────────────┤");
        println!("│ Detection Time: {:<8} ms                                          │", 
                result.detection_time_ms);
        
        if !result.evidence_map.is_empty() {
            println!("├─────────────────────────────────────────────────────────────────────────┤");
            println!("│ Evidence Summary:                                                       │");
            
            for (provider_name, evidence_list) in &result.evidence_map {
                if !evidence_list.is_empty() {
                    println!("│ • {:<20} Evidence Count: {:<3}                          │", 
                            provider_name, evidence_list.len());
                    
                    for (i, evidence) in evidence_list.iter().enumerate() {
                        if i < 3 {
                            let desc = if evidence.description.len() > 45 {
                                format!("{}...", &evidence.description[..42])
                            } else {
                                evidence.description.clone()
                            };
                            println!("│   - {:<45} ({:.0}%) │", desc, evidence.confidence * 100.0);
                            if !evidence.raw_data.is_empty() && evidence.raw_data.len() <= 60 {
                                println!("│     Data: {:<57} │", evidence.raw_data);
                            }
                        }
                    }
                    
                    if evidence_list.len() > 3 {
                        println!("│   ... and {} more evidence items                             │", 
                                evidence_list.len() - 3);
                    }
                }
            }
        }
        
        println!("└─────────────────────────────────────────────────────────────────────────┘");
    }

    fn print_debug_info(&self, result: &DetectionResult) {
        println!("🐛 DEBUG INFO:");
        println!("─────────────────────────────────────────────────────────────────────────────────────");
        println!("URL: {}", result.url);
        println!("Detection Time: {}ms", result.detection_time_ms);
        println!("Timestamp: {}", result.metadata.timestamp.format("%Y-%m-%d %H:%M:%S UTC"));
        println!();
        
        println!("🔍 Provider Scores:");
        if result.provider_scores.is_empty() {
            println!("  No provider scores - no evidence found");
        } else {
            for (provider, score) in &result.provider_scores {
                println!("  {}: {:.1}%", provider, score * 100.0);
            }
        }
        println!();
        
        println!("📝 Evidence Details:");
        for (provider, evidence_list) in &result.evidence_map {
            if !evidence_list.is_empty() {
                println!("  {}:", provider);
                for (i, evidence) in evidence_list.iter().enumerate() {
                    println!("    {}. {} (Confidence: {:.1}%)", 
                             i + 1, evidence.description, evidence.confidence * 100.0);
                    println!("       Method: {:?}", evidence.method_type);
                    println!("       Data: {}", evidence.raw_data);
                    println!("       Signature: {}", evidence.signature_matched);
                }
                println!();
            }
        }
        
        if result.evidence_map.is_empty() {
            println!("  No evidence found");
            println!("  This means either:");
            println!("    • No WAF/CDN is present");
            println!("    • The site uses a WAF/CDN not supported by this tool");
            println!("    • The WAF/CDN is configured to hide its presence");
        }
        
        println!("─────────────────────────────────────────────────────────────────────────────────────");
        println!();
    }

    async fn list_providers(&self) -> Result<()> {
        println!("📋 Available Detection Providers:");
        println!();

        let providers = self.engine.list_providers();
        
        for provider in &providers {
            let status_icon = if provider.enabled { "✅" } else { "❌" };
            
            println!("🔌 {} v{}", provider.name, provider.version);
            println!("   Type: {}", provider.provider_type);
            println!("   Status: {} {}", status_icon, if provider.enabled { "Enabled" } else { "Disabled" });
            println!("   Priority: {}", provider.priority);
            
            if let Some(desc) = &provider.description {
                println!("   Description: {}", desc);
            }
            println!("   Author: WAF-Detector Team");
            println!();
        }

        println!("Total providers: {}", providers.len());
        Ok(())
    }

    async fn start_web_server(&self, port: u16) -> Result<()> {
        println!("🌐 Starting WAF Detector Web Server...");
        
        let web_server = crate::web::WebServer::new(self.engine.clone());
        web_server.start(port).await?;
        
        Ok(())
    }

    async fn run_smoke_test(&self, matches: &ArgMatches) -> Result<()> {
        // Parse URL argument
        let url = matches.get_one::<String>("targets")
            .ok_or_else(|| anyhow!("URL is required for smoke test. Usage: waf-detect --smoke-test <URL>"))?;

        let normalized_url = self.normalize_url(url)?;

        // Parse custom headers
        let mut custom_headers = HashMap::new();
        if let Some(headers) = matches.get_many::<String>("headers") {
            for header in headers {
                if let Some((key, value)) = header.split_once(':') {
                    custom_headers.insert(key.trim().to_string(), value.trim().to_string());
                } else {
                    return Err(anyhow!("Invalid header format: {}. Use 'Key: Value'", header));
                }
            }
        }

        // Configure smoke test
        let mut config = SmokeTestConfig::default();
        config.custom_headers = custom_headers;

        if matches.get_flag("aggressive") {
            config.include_advanced_payloads = true;
            config.delay_between_requests_ms = 50; // Faster for aggressive mode
        }

        // Create and run smoke test
        let smoke_test = WafSmokeTest::new(config)?;
        
        println!("🚀 Starting WAF Smoke Test...");
        println!("═══════════════════════════════════════════════════════════════");
        println!("📊 Test Type │ Payload                        │ Result       │ Code │ Time");
        println!("─────────────┼────────────────────────────────┼──────────────┼──────┼──────");

        let result = smoke_test.run_test(&normalized_url).await?;

        // Print summary
        smoke_test.print_summary(&result);

        // Export to JSON if requested
        if let Some(output_file) = matches.get_one::<String>("output") {
            smoke_test.export_json(&result, output_file)?;
        }

        // Exit with non-zero code if effectiveness is low
        if result.summary.effectiveness_percentage < 50.0 {
            println!("\n⚠️  WARNING: Low WAF effectiveness detected ({:.1}%)", 
                    result.summary.effectiveness_percentage);
            std::process::exit(1);
        }

        Ok(())
    }
}

pub fn build_simple_cli() -> Command {
    Command::new("waf-detect")
        .version("0.1.0")
        .author("WAF Detector Team")
        .about("🔍 Simple WAF/CDN Detection - Just specify domains!")
        .long_about(r#"
🔍 WAF/CDN Detection Tool - Modern CLI

DETECTION USAGE:
  waf-detect cloudflare.com                    # Scan single domain
  waf-detect cloudflare.com discord.com        # Scan multiple domains  
  waf-detect @urls.txt                         # Scan from file
  waf-detect cloudflare.com --json             # JSON output

SMOKE TESTING:
  waf-detect --smoke-test cloudflare.com       # Test WAF effectiveness
  waf-detect --smoke-test example.com -o results.json  # Export results
  waf-detect --smoke-test site.com -H "Authorization: Bearer token"  # Custom headers
  waf-detect --smoke-test site.com --aggressive  # More thorough testing

WEB SERVER:
  waf-detect --web                             # Start web server
  waf-detect --web --port 3000                 # Web server on port 3000

OTHER:
  waf-detect --list                            # List providers

The tool automatically adds https:// if needed and supports both domain names and full URLs.
        "#)
        .arg(
            Arg::new("targets")
                .help("Domain names, URLs, or @file.txt to scan")
                .value_name("TARGET")
                .action(clap::ArgAction::Append)
                .num_args(0..)
        )
        .arg(
            Arg::new("json")
                .long("json")
                .help("Output results in JSON format")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("yaml")
                .long("yaml")
                .help("Output results in YAML format")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("compact")
                .long("compact")
                .short('c')
                .help("Compact one-line output format")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("debug")
                .long("debug")
                .short('d')
                .help("Show detailed debug information")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("verbose")
                .long("verbose")
                .short('v')
                .help("Show verbose scanning progress")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("web")
                .long("web")
                .short('w')
                .help("Start web server mode with beautiful dashboard")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("port")
                .long("port")
                .short('p')
                .help("Port for web server (default: 8080)")
                .value_name("PORT")
                .value_parser(clap::value_parser!(u16))
                .default_value("8080")
        )
        .arg(
            Arg::new("list")
                .long("list")
                .help("List available detection providers")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("smoke-test")
                .long("smoke-test")
                .help("Run comprehensive WAF effectiveness smoke test")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("output")
                .long("output")
                .short('o')
                .help("Export results to JSON file")
                .value_name("FILE")
                .requires("smoke-test")
        )
        .arg(
            Arg::new("headers")
                .long("header")
                .short('H')
                .help("Custom headers for smoke test (format: 'Key: Value')")
                .value_name("HEADER")
                .action(clap::ArgAction::Append)
                .requires("smoke-test")
        )
        .arg(
            Arg::new("aggressive")
                .long("aggressive")
                .help("Enable aggressive testing mode (more payloads, faster)")
                .action(clap::ArgAction::SetTrue)
                .requires("smoke-test")
        )
}

// Backward compatibility aliases
pub use SimpleCliApp as CliApp;
pub use build_simple_cli as build_cli;
