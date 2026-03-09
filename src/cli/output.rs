//! Output formatting for scan results.

use crate::DetectionResult;
use anyhow::Result;

use super::OutputFormat;

pub fn truncate_with_ellipsis(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    if max_chars <= 3 {
        return ".".repeat(max_chars);
    }
    let mut output = String::with_capacity(max_chars);
    for ch in value.chars().take(max_chars - 3) {
        output.push(ch);
    }
    output.push_str("...");
    output
}

pub fn print_compact(result: &DetectionResult) {
    let url_short = truncate_with_ellipsis(&result.url, 40);

    match (&result.detected_waf, &result.detected_cdn) {
        (Some(waf), Some(cdn)) if waf.name == cdn.name => {
            println!(
                "{:<40} {} ({:.1}%)",
                url_short,
                waf.name,
                waf.confidence * 100.0
            );
        }
        (Some(waf), Some(cdn)) => {
            println!(
                "{:<40} WAF: {}, CDN: {} ({:.1}%/{:.1}%)",
                url_short,
                waf.name,
                cdn.name,
                waf.confidence * 100.0,
                cdn.confidence * 100.0
            );
        }
        (Some(waf), None) => {
            println!(
                "{:<40} WAF: {} ({:.1}%)",
                url_short,
                waf.name,
                waf.confidence * 100.0
            );
        }
        (None, Some(cdn)) => {
            println!(
                "{:<40} CDN: {} ({:.1}%)",
                url_short,
                cdn.name,
                cdn.confidence * 100.0
            );
        }
        (None, None) => {
            println!("{:<40} No WAF/CDN detected", url_short);
        }
    }
}

pub fn print_debug_info(result: &DetectionResult) {
    println!("🐛 DEBUG INFO:");
    println!(
        "─────────────────────────────────────────────────────────────────────────────────────"
    );
    println!("URL: {}", result.url);
    println!("Detection Time: {}ms", result.detection_time_ms);
    println!(
        "Timestamp: {}",
        result.metadata.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
    );
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
            println!("  {provider}:");
            for (i, evidence) in evidence_list.iter().enumerate() {
                println!(
                    "    {}. {} (Confidence: {:.1}%)",
                    i + 1,
                    evidence.description,
                    evidence.confidence * 100.0
                );
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

    println!(
        "─────────────────────────────────────────────────────────────────────────────────────"
    );
    println!();
}

pub fn print_table_format(result: &DetectionResult, debug: bool) {
    if debug {
        print_debug_info(result);
    }

    println!("┌─────────────────────────────────────────────────────────────────────────┐");
    println!("│                            WAF/CDN Detection Results                    │");
    println!("├─────────────────────────────────────────────────────────────────────────┤");

    let url_display = truncate_with_ellipsis(&result.url, 67);
    println!("│ URL: {url_display:<67} │");
    println!("├─────────────────────────────────────────────────────────────────────────┤");

    if let Some(waf_detection) = &result.detected_waf {
        println!(
            "│ WAF: {:<20} Confidence: {:<6.1}%                    │",
            waf_detection.name,
            waf_detection.confidence * 100.0
        );
    } else {
        println!("│ WAF: Not Detected                                                      │");
    }

    if let Some(cdn_detection) = &result.detected_cdn {
        println!(
            "│ CDN: {:<20} Confidence: {:<6.1}%                    │",
            cdn_detection.name,
            cdn_detection.confidence * 100.0
        );
    } else {
        println!("│ CDN: Not Detected                                                      │");
    }

    println!("├─────────────────────────────────────────────────────────────────────────┤");
    println!(
        "│ Detection Time: {:<8} ms                                          │",
        result.detection_time_ms
    );

    if !result.evidence_map.is_empty() {
        println!("├─────────────────────────────────────────────────────────────────────────┤");
        println!("│ Evidence Summary:                                                       │");

        for (provider_name, evidence_list) in &result.evidence_map {
            if !evidence_list.is_empty() {
                println!(
                    "│ • {:<20} Evidence Count: {:<3}                          │",
                    provider_name,
                    evidence_list.len()
                );

                for (i, evidence) in evidence_list.iter().enumerate() {
                    if i < 3 {
                        let desc = truncate_with_ellipsis(&evidence.description, 45);
                        println!("│   - {:<45} ({:.0}%) │", desc, evidence.confidence * 100.0);
                        if !evidence.raw_data.is_empty() && evidence.raw_data.len() <= 60 {
                            println!("│     Data: {:<57} │", evidence.raw_data);
                        }
                    }
                }

                if evidence_list.len() > 3 {
                    println!(
                        "│   ... and {} more evidence items                             │",
                        evidence_list.len() - 3
                    );
                }
            }
        }
    }

    println!("└─────────────────────────────────────────────────────────────────────────┘");
}

pub fn print_batch_summary(results: &[DetectionResult], total_time: std::time::Duration) {
    let total = results.len();
    if total == 0 {
        return;
    }

    let waf = results.iter().filter(|r| r.detected_waf.is_some()).count();
    let cdn = results.iter().filter(|r| r.detected_cdn.is_some()).count();
    let both = results
        .iter()
        .filter(|r| r.detected_waf.is_some() && r.detected_cdn.is_some())
        .count();
    let errors = results.iter().filter(|r| r.error.is_some()).count();
    let successful_durations: Vec<u64> = results
        .iter()
        .filter(|r| r.error.is_none())
        .map(|r| r.detection_time_ms)
        .collect();
    let avg_ms = if successful_durations.is_empty() {
        0.0
    } else {
        successful_durations.iter().sum::<u64>() as f64 / successful_durations.len() as f64
    };

    println!();
    println!(
        "Summary: targets={} waf={} cdn={} both={} errors={} avg_scan_ms={:.1} total_time_s={:.2}",
        total,
        waf,
        cdn,
        both,
        errors,
        avg_ms,
        total_time.as_secs_f64()
    );
}

/// Emit scan results in the requested format. Handles Json, Ndjson, Yaml, Compact, and Table.
pub fn emit_scan_results(
    results: &[DetectionResult],
    format: &OutputFormat,
    debug: bool,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(results)?);
        }
        OutputFormat::Ndjson => {
            for result in results {
                println!("{}", serde_json::to_string(result)?);
            }
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yml::to_string(results)?);
        }
        OutputFormat::Compact => {
            for result in results {
                print_compact(result);
            }
        }
        OutputFormat::Table => {
            for (i, result) in results.iter().enumerate() {
                if i > 0 {
                    println!();
                }
                print_table_format(result, debug);
            }
        }
    }
    Ok(())
}
