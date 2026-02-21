//! Simple CLI Interface - Modern and intuitive WAF detection

use crate::engine::DetectionEngine;
use crate::payload::waf_smoke_test::{SmokeTestConfig, WafSmokeTest};
use crate::posture::PostureBuilder;
use crate::providers::{
    akamai::AkamaiProvider, aws::AwsProvider, azure::AzureProvider, cloudflare::CloudFlareProvider,
    f5::F5Provider, fastly::FastlyProvider, fortiweb::FortiWebProvider, imperva::ImpervaProvider,
    modsecurity::ModSecurityProvider, radware::RadwareProvider, sucuri::SucuriProvider,
    vercel::VercelProvider, Provider,
};
use crate::registry::ProviderRegistry;
use crate::virtual_adversary::{VirtualAdversaryConfig, VirtualAdversaryRunner};
use crate::virtual_adversary2::{build_va2_campaign_plan, Va2CampaignConfig, Va2Phase, Va2Runner};
use crate::DetectionResult;
use anyhow::{anyhow, Result};
use clap::{Arg, ArgMatches, Command};
use std::collections::HashMap;
use std::fs;
use std::time::Instant;
use url::Url;

mod benchmark;
pub use benchmark::BenchmarkReport;
use benchmark::{BenchmarkMode, BenchmarkOptions};

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn parse_va2_phases(raw: &str) -> Result<Vec<Va2Phase>> {
    let mut phases = Vec::new();
    for item in raw.split(',') {
        let phase = match item.trim().to_lowercase().as_str() {
            "baseline" => Va2Phase::Baseline,
            "protocol-variance" => Va2Phase::ProtocolVariance,
            "state-escalation" => Va2Phase::StateEscalation,
            "behavioral-pressure" => Va2Phase::BehavioralPressure,
            "challenge-interaction" => Va2Phase::ChallengeInteraction,
            other => return Err(anyhow!("unknown va2 phase: {other}")),
        };
        phases.push(phase);
    }
    if phases.is_empty() {
        return Err(anyhow!("va2 phases cannot be empty"));
    }
    Ok(phases)
}

fn parse_benchmark_mode(raw: &str) -> Result<BenchmarkMode> {
    match raw.trim().to_lowercase().as_str() {
        "live" => Ok(BenchmarkMode::Live),
        "fixture" => Ok(BenchmarkMode::Fixture),
        other => Err(anyhow!(
            "invalid benchmark mode '{other}' (expected live|fixture)"
        )),
    }
}

fn feature_enabled(env_key: &str) -> bool {
    std::env::var(env_key)
        .map(|value| {
            let trimmed = value.trim().to_lowercase();
            trimmed == "1" || trimmed == "true" || trimmed == "yes" || trimmed == "on"
        })
        .unwrap_or(false)
}

fn load_effectiveness_overrides(
    path: &str,
) -> Result<crate::effectiveness::EffectivenessConfigOverrides> {
    let contents = fs::read_to_string(path)?;
    let overrides = toml::from_str(&contents)
        .map_err(|err| anyhow!("Failed to parse effectiveness config TOML {path}: {err}"))?;
    Ok(overrides)
}

pub struct SimpleCliApp {
    registry: ProviderRegistry,
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
        registry.register_provider(Provider::Azure(AzureProvider::new()))?;
        registry.register_provider(Provider::F5(F5Provider::new()))?;
        registry.register_provider(Provider::Imperva(ImpervaProvider::new()))?;
        registry.register_provider(Provider::ModSecurity(ModSecurityProvider::new()))?;
        registry.register_provider(Provider::Sucuri(SucuriProvider::new()))?;
        registry.register_provider(Provider::Radware(RadwareProvider::new()))?;
        registry.register_provider(Provider::FortiWeb(FortiWebProvider::new()))?;

        Ok(Self { registry })
    }

    pub async fn run(&self) -> Result<()> {
        let matches = build_simple_cli().get_matches();
        self.run_with_matches(matches).await
    }

    pub async fn run_with_matches(&self, matches: ArgMatches) -> Result<()> {
        let mode = crate::DeploymentMode::from_env();
        tracing::info!("WAF Detector running in {:?} mode", mode);

        let payload_analysis_enabled = matches.get_flag("payload-analysis");
        self.registry
            .set_payload_analysis_enabled(payload_analysis_enabled);
        let engine = DetectionEngine::new(self.registry.clone())?.with_waf_mode_detection();

        // Handle special commands first
        if matches.get_flag("web") {
            let port = matches.get_one::<u16>("port").copied().unwrap_or(8080);
            return self.start_web_server(&engine, port).await;
        }

        if matches.get_flag("list") {
            return self.list_providers(&engine).await;
        }

        // Handle consent command
        if let Some(consent_args) = matches.get_many::<String>("consent") {
            let args: Vec<String> = consent_args.cloned().collect();
            return crate::effectiveness::consent::manage_consent_cli(args);
        }

        // Handle benchmark evaluation
        if let Some(corpus_path) = matches.get_one::<String>("benchmark") {
            let result = self.run_benchmark(&engine, corpus_path, &matches).await;
            self.write_perf_report_if_requested(&matches)?;
            return result;
        }

        // Handle effectiveness testing
        if let Some(url) = matches.get_one::<String>("effectiveness") {
            return self.run_effectiveness_test(url, &matches).await;
        }

        // Handle smoke test command
        if matches.get_flag("smoke-test") {
            return self.run_smoke_test(&matches).await;
        }

        // Handle virtual adversary (VA) schema output
        if matches.get_flag("va-schema") {
            let schema = crate::virtual_adversary::va_report_schema();
            println!("{}", serde_json::to_string_pretty(&schema)?);
            return Ok(());
        }

        // Handle explicit posture summary (feature-gated)
        if let Some(url) = matches.get_one::<String>("posture-summary") {
            if !feature_enabled("WAF_DETECTOR_POSTURE_SUMMARY") {
                return Err(anyhow!(
                    "posture summary is disabled. Set WAF_DETECTOR_POSTURE_SUMMARY=1 to enable."
                ));
            }

            let normalized = self.normalize_url(url)?;
            let detection_result = engine.detect(&normalized).await?;
            let phases = parse_va2_phases("baseline,protocol-variance")?;
            let mut plan = build_va2_campaign_plan(
                &normalized,
                &phases,
                Va2CampaignConfig {
                    seed: 1337,
                    budget: 12,
                },
            )?;
            for step in &mut plan.steps {
                step.delay_ms = 0;
            }
            let runner = Va2Runner::new()?;
            let va2_report = runner.run_plan(plan).await?;
            let summary = crate::posture::compose_posture_summary(
                Some(&detection_result),
                Some(&va2_report),
                None,
            );
            println!("{}", serde_json::to_string_pretty(&summary)?);
            self.write_perf_report_if_requested(&matches)?;
            return Ok(());
        }

        // Handle posture report
        if let Some(url) = matches.get_one::<String>("posture") {
            let normalized = self.normalize_url(url)?;
            let detection_result = engine.detect(&normalized).await?;
            let mut builder = PostureBuilder::new(&normalized).with_detection(&detection_result);

            if matches.get_flag("posture-va2") {
                let phases_raw = "baseline,protocol-variance";
                let phases = parse_va2_phases(phases_raw)?;
                let config = Va2CampaignConfig::default();
                let mut plan = build_va2_campaign_plan(&normalized, &phases, config)?;
                for step in &mut plan.steps {
                    step.delay_ms = 0;
                }
                let runner = Va2Runner::new()?;
                let report = runner.run_plan(plan).await?;
                builder = builder.with_va2(&report);
            }

            let posture = builder.compute();

            if matches.get_flag("posture-json") {
                println!("{}", serde_json::to_string_pretty(&posture)?);
            } else {
                println!("Posture Report: {}", posture.target_url);
                println!("  Grade:      {}", posture.grade);
                println!("  Risk Score: {:.1}", posture.risk_score);
                if let Some(det) = &posture.detection {
                    if det.waf_detected {
                        println!(
                            "  WAF:        {} ({:.0}%)",
                            det.waf_name.as_deref().unwrap_or("Unknown"),
                            det.waf_confidence * 100.0
                        );
                    } else {
                        println!("  WAF:        Not detected");
                    }
                }
                if let Some(beh) = &posture.behavioral {
                    println!("  VA2 PMI:    {:.0} ({})", beh.pmi_score, beh.pmi_label);
                }
                if let Some(enf) = &posture.enforcement {
                    println!(
                        "  VA1:        {} ({:.0}%)",
                        enf.enforcement,
                        enf.confidence_score * 100.0
                    );
                }
                println!("  Summary:    {}", posture.summary);
            }
            self.write_perf_report_if_requested(&matches)?;
            return Ok(());
        }

        // Handle virtual adversary 2.0 (VA2)
        if let Some(url) = matches.get_one::<String>("va2") {
            let phases_raw = matches
                .get_one::<String>("va2-phases")
                .map(String::as_str)
                .unwrap_or("baseline,protocol-variance");
            let phases = parse_va2_phases(phases_raw)?;
            let config = Va2CampaignConfig {
                seed: *matches.get_one::<u64>("va2-seed").unwrap_or(&1337),
                budget: *matches.get_one::<u32>("va2-budget").unwrap_or(&60),
            };
            let plan = build_va2_campaign_plan(url, &phases, config)?;

            if matches.get_flag("va2-run") {
                let runner = Va2Runner::new()?;
                let report = runner.run_plan(plan).await?;
                let errors = report
                    .results
                    .iter()
                    .filter(|result| result.error.is_some())
                    .count();
                println!(
                    "🧪 VA2 Run: {} steps | errors {}",
                    report.results.len(),
                    errors
                );
                if let Some(cc) = &report.channel_coverage {
                    println!("\nChannel Coverage:");
                    let mut channels: Vec<_> = cc.channels.iter().collect();
                    channels.sort_by_key(|(ch, _)| format!("{ch:?}"));
                    for (ch, rate) in &channels {
                        let disc_count = report
                            .differential
                            .iter()
                            .filter(|d| d.channel == Some(**ch) && d.discriminated)
                            .count();
                        let total_count = report
                            .differential
                            .iter()
                            .filter(|d| d.channel == Some(**ch))
                            .count();
                        let blind = if cc.blind_spots.contains(ch) {
                            " [blind spot]"
                        } else {
                            ""
                        };
                        println!(
                            "  {:<8} {:>3.0}% ({}/{}){}",
                            ch.to_string() + ":",
                            *rate * 100.0,
                            disc_count,
                            total_count,
                            blind
                        );
                    }
                    println!("  Overall: {:.0}%", cc.coverage_score * 100.0);
                }
                self.write_perf_report_if_requested(&matches)?;
                return Ok(());
            }

            if matches.get_flag("va2-json") {
                let json = serde_json::to_string_pretty(&plan)?;
                println!("{json}");
                self.write_perf_report_if_requested(&matches)?;
                return Ok(());
            }

            if let Some(output) = matches.get_one::<String>("va2-output") {
                let json = serde_json::to_string_pretty(&plan)?;
                fs::write(output, json)?;
                println!("📄 VA2 plan saved to: {output}");
                self.write_perf_report_if_requested(&matches)?;
                return Ok(());
            }

            println!(
                "🧭 VA2 Dry Run: {} steps across {} phases (seed={}, budget={})",
                plan.steps.len(),
                plan.phases.len(),
                plan.seed,
                plan.budget
            );
            self.write_perf_report_if_requested(&matches)?;
            return Ok(());
        }

        // Handle virtual adversary (VA) mode
        if let Some(replay_path) = matches.get_one::<String>("va-replay-run") {
            let raw = fs::read_to_string(replay_path)?;
            let report = serde_json::from_str::<crate::virtual_adversary::VaRunReport>(&raw)
                .or_else(|_| {
                    serde_json::from_str::<crate::web::VaStoredReport>(&raw)
                        .map(|stored| stored.report)
                })
                .map_err(|err| anyhow!("failed to parse replay report: {err}"))?;
            let target = matches
                .get_one::<String>("va-replay-target")
                .cloned()
                .unwrap_or_else(|| report.target_url.clone());
            let mut runner = VirtualAdversaryRunner::new(report.config.clone())?;
            let report = runner.run_replay_plan(&target, report.replay_plan.clone())?;

            if matches.get_flag("va-json") {
                let json = serde_json::to_string_pretty(&report)?;
                println!("{json}");
                self.write_perf_report_if_requested(&matches)?;
                return Ok(());
            }
            if matches.get_flag("va-replay") {
                let json = serde_json::to_string_pretty(&report.replay_plan)?;
                println!("{json}");
                self.write_perf_report_if_requested(&matches)?;
                return Ok(());
            }
            if matches.get_flag("va-replay-csv") {
                let mut lines = Vec::new();
                lines.push(
                    "index,probe_class,probe_channel,probe_description,method,url,headers,body"
                        .to_string(),
                );
                for item in &report.replay_plan {
                    let row = [
                        item.index.to_string(),
                        csv_escape(&item.class),
                        csv_escape(&item.channel),
                        csv_escape(&item.description),
                        csv_escape(&item.method),
                        csv_escape(&item.url),
                        csv_escape(&serde_json::to_string(&item.headers).unwrap_or_default()),
                        csv_escape(&item.body.clone().unwrap_or_default()),
                    ]
                    .join(",");
                    lines.push(row);
                }
                println!("{}", lines.join("\n"));
                self.write_perf_report_if_requested(&matches)?;
                return Ok(());
            }
            if let Some(output) = matches.get_one::<String>("va-output") {
                let json = serde_json::to_string_pretty(&report)?;
                std::fs::write(output, json)?;
                let summary_path = format!("{}.summary.txt", output.trim_end_matches(".json"));
                let summary = format!(
                    "target={}\nconfidence={:.2}\nrisk={}\nblocked={}\nchallenge={}\nallowed={}\nerror={}\n",
                    report.target_url,
                    report.summary.confidence_score(),
                    report.summary.risk_label(),
                    report.summary.blocked,
                    report.summary.challenge,
                    report.summary.allowed,
                    report.summary.error
                );
                std::fs::write(&summary_path, summary)?;
                println!("📄 VA replay report saved to: {output}");
                println!("📄 VA replay summary saved to: {summary_path}");
                self.write_perf_report_if_requested(&matches)?;
                return Ok(());
            }
            println!(
                "🧪 Virtual Adversary Replay: {} | Total: {} | Blocked: {} | Challenge: {} | Allowed: {} | Error: {} | Confidence: {:.2} | Risk: {} | Enforcement: {:?} | Evidence: {:.2}",
                report.target_url,
                report.summary.total,
                report.summary.blocked,
                report.summary.challenge,
                report.summary.allowed,
                report.summary.error,
                report.summary.confidence_score(),
                report.summary.risk_label(),
                report.enforcement,
                report.evidence_score
            );
            let max_results = *matches.get_one::<u8>("va-top").unwrap_or(&3) as usize;
            if !report.results.is_empty() {
                println!("   Top Results:");
                let reason_level = *matches.get_one::<u8>("va-reason-level").unwrap_or(&1);
                let max_len = *matches.get_one::<u16>("va-max-len").unwrap_or(&80) as usize;
                for result in report.results.iter().take(max_results) {
                    let payload = if result.payload.len() > max_len {
                        format!("{}...", &result.payload[..max_len.saturating_sub(3)])
                    } else {
                        result.payload.clone()
                    };
                    if reason_level == 0 {
                        println!(
                            "   - {:?} | {} | {:?}",
                            result.category, payload, result.outcome
                        );
                    } else {
                        println!(
                            "   - {:?} | {} | {:?} | {}",
                            result.category, payload, result.outcome, result.reason
                        );
                    }
                }
            }
            self.write_perf_report_if_requested(&matches)?;
            return Ok(());
        }

        if let Some(url) = matches.get_one::<String>("va") {
            let config = VirtualAdversaryConfig {
                tier: *matches.get_one::<u8>("va-tier").unwrap_or(&1),
                request_budget: *matches.get_one::<u32>("va-budget").unwrap_or(&120),
                request_timeout: std::time::Duration::from_secs(
                    *matches.get_one::<u64>("va-timeout").unwrap_or(&15),
                ),
                request_delay: std::time::Duration::from_millis(
                    *matches.get_one::<u64>("va-delay").unwrap_or(&750),
                ),
                max_variants_per_payload: *matches.get_one::<u8>("va-variants").unwrap_or(&4),
                skip_dns_validation: false,
            };
            let mut runner = VirtualAdversaryRunner::new(config)?;
            if matches.get_flag("va-dry-run") {
                let plan = runner.plan(url);
                println!("🧪 VA Dry Run: {} planned probes", plan.len());
                for probe in plan {
                    println!(
                        " - {:?}::{:?}: {}",
                        probe.probe.class, probe.probe.channel, probe.display
                    );
                }
                self.write_perf_report_if_requested(&matches)?;
                return Ok(());
            }
            let report = runner.run(url)?;
            if matches.get_flag("va-json") {
                let json = serde_json::to_string_pretty(&report)?;
                println!("{json}");
                self.write_perf_report_if_requested(&matches)?;
                return Ok(());
            }
            if matches.get_flag("va-replay") {
                let json = serde_json::to_string_pretty(&report.replay_plan)?;
                println!("{json}");
                self.write_perf_report_if_requested(&matches)?;
                return Ok(());
            }
            if matches.get_flag("va-replay-csv") {
                let mut lines = Vec::new();
                lines.push(
                    "index,probe_class,probe_channel,probe_description,method,url,headers,body"
                        .to_string(),
                );
                for item in &report.replay_plan {
                    let row = [
                        item.index.to_string(),
                        csv_escape(&item.class),
                        csv_escape(&item.channel),
                        csv_escape(&item.description),
                        csv_escape(&item.method),
                        csv_escape(&item.url),
                        csv_escape(&serde_json::to_string(&item.headers).unwrap_or_default()),
                        csv_escape(&item.body.clone().unwrap_or_default()),
                    ]
                    .join(",");
                    lines.push(row);
                }
                println!("{}", lines.join("\n"));
                self.write_perf_report_if_requested(&matches)?;
                return Ok(());
            }
            if let Some(output) = matches.get_one::<String>("va-output") {
                let json = serde_json::to_string_pretty(&report)?;
                std::fs::write(output, json)?;
                let summary_path = format!("{}.summary.txt", output.trim_end_matches(".json"));
                let summary = format!(
                    "target={}\nconfidence={:.2}\nrisk={}\nblocked={}\nchallenge={}\nallowed={}\nerror={}\n",
                    report.target_url,
                    report.summary.confidence_score(),
                    report.summary.risk_label(),
                    report.summary.blocked,
                    report.summary.challenge,
                    report.summary.allowed,
                    report.summary.error
                );
                std::fs::write(&summary_path, summary)?;
                println!("📄 VA report saved to: {output}");
                println!("📄 VA summary saved to: {summary_path}");
                self.write_perf_report_if_requested(&matches)?;
                return Ok(());
            }
            println!(
                "🧪 Virtual Adversary: {} | Total: {} | Blocked: {} | Challenge: {} | Allowed: {} | Error: {} | Confidence: {:.2} | Risk: {} | Enforcement: {:?} | Evidence: {:.2}",
                report.target_url,
                report.summary.total,
                report.summary.blocked,
                report.summary.challenge,
                report.summary.allowed,
                report.summary.error,
                report.summary.confidence_score(),
                report.summary.risk_label(),
                report.enforcement,
                report.evidence_score
            );
            println!(
                "   Config: tier={} budget={} delay_ms={} timeout_s={} variants={}",
                report.config.tier,
                report.config.request_budget,
                report.config.request_delay.as_millis(),
                report.config.request_timeout.as_secs(),
                report.config.max_variants_per_payload
            );
            let max_results = *matches.get_one::<u8>("va-top").unwrap_or(&3) as usize;
            if !report.results.is_empty() {
                println!("   Top Results:");
                let reason_level = *matches.get_one::<u8>("va-reason-level").unwrap_or(&1);
                let max_len = *matches.get_one::<u16>("va-max-len").unwrap_or(&80) as usize;
                for result in report.results.iter().take(max_results) {
                    let payload = if result.payload.len() > max_len {
                        format!("{}...", &result.payload[..max_len.saturating_sub(3)])
                    } else {
                        result.payload.clone()
                    };
                    if reason_level == 0 {
                        println!(
                            "   - {:?} | {} | {:?}",
                            result.category, payload, result.outcome
                        );
                    } else {
                        println!(
                            "   - {:?} | {} | {:?} | {}",
                            result.category, payload, result.outcome, result.reason
                        );
                    }
                }
            }
            self.write_perf_report_if_requested(&matches)?;
            return Ok(());
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
        let result = if targets.len() == 1 {
            self.scan_single(&engine, &targets[0], &format, debug, verbose)
                .await
        } else {
            self.scan_batch(&engine, &targets, &format, debug, verbose)
                .await
        };
        self.write_perf_report_if_requested(&matches)?;
        result
    }

    fn parse_targets(&self, matches: &ArgMatches) -> Result<Vec<String>> {
        let mut targets = Vec::new();

        // Get targets from direct arguments
        if let Some(domains) = matches.get_many::<String>("targets") {
            for domain in domains {
                if let Some(filename) = domain.strip_prefix('@') {
                    // File input: @file.txt
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
        let with_https = format!("https://{input}");
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

    fn write_perf_report_if_requested(&self, matches: &ArgMatches) -> Result<()> {
        if let Some(path) = matches.get_one::<String>("perf-report") {
            let snapshot = crate::perf::snapshot();
            let json = serde_json::to_string_pretty(&snapshot)?;
            fs::write(path, json)?;
            println!("📈 Performance report saved to: {path}");
        }
        Ok(())
    }

    async fn scan_single(
        &self,
        engine: &DetectionEngine,
        url: &str,
        format: &str,
        debug: bool,
        verbose: bool,
    ) -> Result<()> {
        if verbose {
            println!("🔍 Scanning: {url}");
        }

        let start_time = Instant::now();
        let detection_result = engine.detect(url).await?;
        let scan_time = start_time.elapsed();

        match format {
            "json" => {
                println!("{}", serde_json::to_string_pretty(&detection_result)?);
            }
            "yaml" => {
                println!("{}", serde_yml::to_string(&detection_result)?);
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

    async fn scan_batch(
        &self,
        engine: &DetectionEngine,
        urls: &[String],
        format: &str,
        debug: bool,
        verbose: bool,
    ) -> Result<()> {
        if verbose {
            println!("🔍 Scanning {} targets...", urls.len());
        }

        let total_start = Instant::now();

        // Use parallel batch detection with rate limiting (max 3 concurrent requests)
        let url_refs: Vec<&str> = urls.iter().map(|s| s.as_str()).collect();
        let batch_results = engine.detect_batch(&url_refs, 3).await?;

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
                println!("{}", serde_yml::to_string(&results)?);
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
                println!("{url_short:<40} Not Detected");
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
        println!("│ URL: {url_display:<67} │");
        println!("├─────────────────────────────────────────────────────────────────────────┤");

        // WAF Detection
        if let Some(waf_detection) = &result.detected_waf {
            println!(
                "│ WAF: {:<20} Confidence: {:<6.1}%                    │",
                waf_detection.name,
                waf_detection.confidence * 100.0
            );
        } else {
            println!("│ WAF: Not Detected                                                      │");
        }

        // CDN Detection
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

    fn print_debug_info(&self, result: &DetectionResult) {
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

    async fn list_providers(&self, engine: &DetectionEngine) -> Result<()> {
        println!("📋 Available Detection Providers:");
        println!();

        let providers = engine.list_providers();

        for provider in &providers {
            let status_icon = if provider.enabled { "✅" } else { "❌" };

            println!("🔌 {} v{}", provider.name, provider.version);
            println!("   Type: {}", provider.provider_type);
            println!(
                "   Status: {} {}",
                status_icon,
                if provider.enabled {
                    "Enabled"
                } else {
                    "Disabled"
                }
            );
            println!("   Priority: {}", provider.priority);

            if let Some(desc) = &provider.description {
                println!("   Description: {desc}");
            }
            println!("   Author: WAF-Detector Team");
            println!();
        }

        println!("Total providers: {}", providers.len());
        Ok(())
    }

    async fn start_web_server(&self, engine: &DetectionEngine, port: u16) -> Result<()> {
        println!("🌐 Starting WAF Detector Web Server...");

        let mut last_error: Option<anyhow::Error> = None;
        let max_attempts = 10u16;

        for offset in 0..max_attempts {
            let candidate = port.saturating_add(offset);
            let web_server = crate::web::WebServer::new(engine.clone());
            match web_server.start(candidate).await {
                Ok(()) => return Ok(()),
                Err(err) => {
                    let addr_in_use = err
                        .downcast_ref::<std::io::Error>()
                        .map(|io_err| io_err.kind() == std::io::ErrorKind::AddrInUse)
                        .unwrap_or(false);
                    if addr_in_use {
                        println!("⚠️  Port {candidate} is in use, trying next port...");
                        last_error = Some(err);
                        continue;
                    }
                    return Err(err);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow!("Unable to bind to a free port")))
    }

    async fn run_effectiveness_test(&self, url: &str, matches: &ArgMatches) -> Result<()> {
        use crate::effectiveness::{EffectivenessConfig, EffectivenessTest};

        println!("🔍 WAF Effectiveness Testing");
        println!("════════════════════════════════════════════════════════════════");

        // Create effectiveness test with default config
        let mut config = EffectivenessConfig::default();
        if let Some(path) = matches.get_one::<String>("effectiveness-config") {
            let overrides = load_effectiveness_overrides(path)?;
            config.apply_overrides(overrides);
        }

        if let Some(value) = matches.get_one::<f64>("effectiveness-similarity-threshold") {
            if !(0.0..=1.0).contains(value) {
                return Err(anyhow!(
                    "effectiveness-similarity-threshold must be between 0.0 and 1.0"
                ));
            }
            config.similarity_threshold = *value;
        }
        if let Some(value) = matches.get_one::<f64>("effectiveness-reduction-ratio") {
            if !(0.0..=1.0).contains(value) {
                return Err(anyhow!(
                    "effectiveness-reduction-ratio must be between 0.0 and 1.0"
                ));
            }
            config.reduction_ratio = *value;
        }
        if let Some(value) = matches.get_one::<usize>("effectiveness-min-length-diff") {
            if *value == 0 {
                return Err(anyhow!(
                    "effectiveness-min-length-diff must be greater than 0"
                ));
            }
            config.min_length_diff = *value;
        }

        let mut test = EffectivenessTest::new(config).await?;

        // Run the test
        println!("🎯 Target: {url}");
        println!("⏳ Running comprehensive effectiveness tests...\n");

        let report = test.test_effectiveness(url).await?;

        // Display results
        println!("\n{}", report.generate_summary());

        // Save report if high risk
        if report.risk_score > 50.0 {
            let filename = format!(
                "waf-effectiveness-{}.json",
                chrono::Utc::now().format("%Y%m%d_%H%M%S")
            );
            std::fs::write(&filename, report.to_json()?)?;
            println!("\n📁 High-risk report saved to: {filename}");
        }

        Ok(())
    }

    async fn run_benchmark(
        &self,
        engine: &DetectionEngine,
        corpus_path: &str,
        matches: &ArgMatches,
    ) -> Result<()> {
        let corpus_json = fs::read_to_string(corpus_path)
            .map_err(|e| anyhow!("Failed to read corpus file '{}': {}", corpus_path, e))?;
        let corpus: benchmark::BenchmarkCorpus = serde_json::from_str(&corpus_json)
            .map_err(|e| anyhow!("Failed to parse corpus JSON: {}", e))?;

        println!("📊 WAF/CDN Detection Benchmark");
        println!(
            "   Corpus: {} ({} entries)",
            corpus_path,
            corpus.entries.len()
        );
        println!();

        let workers: usize = *matches.get_one::<usize>("benchmark-workers").unwrap_or(&3);
        let mode_raw = if let Some(mode) = matches.get_one::<String>("benchmark-mode") {
            mode.clone()
        } else if feature_enabled("WAF_DETECTOR_FIXTURE_MODE") {
            "fixture".to_string()
        } else {
            "live".to_string()
        };
        let mode = parse_benchmark_mode(&mode_raw)?;
        let fixtures_dir = matches
            .get_one::<String>("benchmark-fixtures")
            .map(std::path::PathBuf::from);
        let options = BenchmarkOptions { mode, fixtures_dir };

        let report =
            benchmark::run_benchmark_with_options(engine, &corpus, workers, &options).await?;

        // Print human-readable summary
        report.print_summary();

        // Save JSON report if output path specified
        if let Some(output) = matches.get_one::<String>("benchmark-output") {
            let json = serde_json::to_string_pretty(&report)?;
            fs::write(output, &json)?;
            println!("\n📁 Benchmark report saved to: {output}");
        }

        Ok(())
    }

    async fn run_smoke_test(&self, matches: &ArgMatches) -> Result<()> {
        // Parse URL argument
        let url = matches.get_one::<String>("targets").ok_or_else(|| {
            anyhow!("URL is required for smoke test. Usage: waf-detect --smoke-test <URL>")
        })?;

        let normalized_url = self.normalize_url(url)?;

        // Parse custom headers
        let mut custom_headers = HashMap::new();
        if let Some(headers) = matches.get_many::<String>("headers") {
            for header in headers {
                if let Some((key, value)) = header.split_once(':') {
                    custom_headers.insert(key.trim().to_string(), value.trim().to_string());
                } else {
                    return Err(anyhow!(
                        "Invalid header format: {}. Use 'Key: Value'",
                        header
                    ));
                }
            }
        }

        // Configure smoke test
        let mut config = SmokeTestConfig {
            custom_headers,
            ..Default::default()
        };

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
            println!(
                "\n⚠️  WARNING: Low WAF effectiveness detected ({:.1}%)",
                result.summary.effectiveness_percentage
            );
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
        .long_about(
            r#"
🔍 WAF/CDN Detection Tool - Modern CLI

DETECTION USAGE:
  waf-detect cloudflare.com                    # Scan single domain
  waf-detect cloudflare.com discord.com        # Scan multiple domains  
  waf-detect @urls.txt                         # Scan from file
  waf-detect cloudflare.com --json             # JSON output
  waf-detect example.com --payload-analysis    # Enable active payload probing (authorized targets only)

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
        "#,
        )
        .arg(
            Arg::new("targets")
                .help("Domain names, URLs, or @file.txt to scan")
                .value_name("TARGET")
                .action(clap::ArgAction::Append)
                .num_args(0..),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .help("Output results in JSON format")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("yaml")
                .long("yaml")
                .help("Output results in YAML format")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("compact")
                .long("compact")
                .short('c')
                .help("Compact one-line output format")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("debug")
                .long("debug")
                .short('d')
                .help("Show detailed debug information")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("verbose")
                .long("verbose")
                .short('v')
                .help("Show verbose scanning progress")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("payload-analysis")
                .long("payload-analysis")
                .help(
                    "Enable active payload-based probing during detection (authorized targets only)",
                )
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("web")
                .long("web")
                .short('w')
                .help("Start web server mode with beautiful dashboard")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("port")
                .long("port")
                .short('p')
                .help("Port for web server (default: 8080)")
                .value_name("PORT")
                .value_parser(clap::value_parser!(u16))
                .default_value("8080"),
        )
        .arg(
            Arg::new("list")
                .long("list")
                .help("List available detection providers")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("smoke-test")
                .long("smoke-test")
                .help("Run comprehensive WAF effectiveness smoke test")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .short('o')
                .help("Export results to JSON file")
                .value_name("FILE")
                .requires("smoke-test"),
        )
        .arg(
            Arg::new("headers")
                .long("header")
                .short('H')
                .help("Custom headers for smoke test (format: 'Key: Value')")
                .value_name("HEADER")
                .action(clap::ArgAction::Append)
                .requires("smoke-test"),
        )
        .arg(
            Arg::new("aggressive")
                .long("aggressive")
                .help("Enable aggressive testing mode (more payloads, faster)")
                .action(clap::ArgAction::SetTrue)
                .requires("smoke-test"),
        )
        .arg(
            Arg::new("benchmark")
                .long("benchmark")
                .help("Run offline detection benchmark against a labeled corpus JSON file")
                .value_name("FILE")
                .num_args(1),
        )
        .arg(
            Arg::new("benchmark-output")
                .long("benchmark-output")
                .help("Save benchmark results as JSON to file")
                .value_name("FILE")
                .requires("benchmark"),
        )
        .arg(
            Arg::new("benchmark-workers")
                .long("benchmark-workers")
                .help("Number of concurrent detection workers for benchmark (default: 3)")
                .value_name("COUNT")
                .value_parser(clap::value_parser!(usize))
                .default_value("3")
                .requires("benchmark"),
        )
        .arg(
            Arg::new("benchmark-mode")
                .long("benchmark-mode")
                .help("Benchmark execution mode: live network or fixture replay")
                .value_name("MODE")
                .value_parser(["live", "fixture"])
                .default_value("live")
                .requires("benchmark"),
        )
        .arg(
            Arg::new("benchmark-fixtures")
                .long("benchmark-fixtures")
                .help("Directory containing benchmark fixture corpus (fixtures.json)")
                .value_name("DIR")
                .requires("benchmark"),
        )
        .arg(
            Arg::new("consent")
                .long("consent")
                .help("Manage consent for effectiveness testing")
                .value_name("COMMAND")
                .num_args(0..),
        )
        .arg(
            Arg::new("effectiveness")
                .long("effectiveness")
                .help("Run comprehensive WAF effectiveness testing (requires consent)")
                .value_name("URL")
                .num_args(1),
        )
        .arg(
            Arg::new("effectiveness-config")
                .long("effectiveness-config")
                .help("Path to TOML config overrides for effectiveness testing")
                .value_name("FILE")
                .requires("effectiveness"),
        )
        .arg(
            Arg::new("effectiveness-similarity-threshold")
                .long("effectiveness-similarity-threshold")
                .help("Override response body similarity threshold (0.0-1.0)")
                .value_name("FLOAT")
                .value_parser(clap::value_parser!(f64))
                .requires("effectiveness"),
        )
        .arg(
            Arg::new("effectiveness-reduction-ratio")
                .long("effectiveness-reduction-ratio")
                .help("Override response body reduction ratio (0.0-1.0)")
                .value_name("FLOAT")
                .value_parser(clap::value_parser!(f64))
                .requires("effectiveness"),
        )
        .arg(
            Arg::new("effectiveness-min-length-diff")
                .long("effectiveness-min-length-diff")
                .help("Override minimum response body length diff")
                .value_name("BYTES")
                .value_parser(clap::value_parser!(usize))
                .requires("effectiveness"),
        )
        .arg(
            Arg::new("va2")
                .long("va2")
                .help("Run Virtual Adversary 2.0 dry run (behavioral campaign)")
                .value_name("URL")
                .num_args(1),
        )
        .arg(
            Arg::new("va2-dry-run")
                .long("va2-dry-run")
                .help("Print VA2 plan summary without execution")
                .action(clap::ArgAction::SetTrue)
                .requires("va2"),
        )
        .arg(
            Arg::new("va2-run")
                .long("va2-run")
                .help("Execute VA2 campaign plan (requires consent)")
                .action(clap::ArgAction::SetTrue)
                .requires("va2"),
        )
        .arg(
            Arg::new("va2-json")
                .long("va2-json")
                .help("Print VA2 plan JSON to stdout")
                .action(clap::ArgAction::SetTrue)
                .requires("va2"),
        )
        .arg(
            Arg::new("va2-output")
                .long("va2-output")
                .help("Write VA2 plan JSON to file")
                .value_name("FILE")
                .requires("va2"),
        )
        .arg(
            Arg::new("va2-phases")
                .long("va2-phases")
                .help("VA2 phases (comma-separated)")
                .value_name("LIST")
                .default_value("baseline,protocol-variance")
                .requires("va2"),
        )
        .arg(
            Arg::new("va2-seed")
                .long("va2-seed")
                .help("VA2 deterministic seed")
                .value_name("SEED")
                .value_parser(clap::value_parser!(u64))
                .default_value("1337")
                .requires("va2"),
        )
        .arg(
            Arg::new("va2-budget")
                .long("va2-budget")
                .help("VA2 request budget")
                .value_name("COUNT")
                .value_parser(clap::value_parser!(u32))
                .default_value("60")
                .requires("va2"),
        )
        .arg(
            Arg::new("posture")
                .long("posture")
                .help("Generate unified posture report (detection + optional VA2/VA1)")
                .value_name("URL")
                .num_args(1),
        )
        .arg(
            Arg::new("posture-summary")
                .long("posture-summary")
                .help("Generate posture summary JSON (detection + VA2 paired-control)")
                .value_name("URL")
                .num_args(1),
        )
        .arg(
            Arg::new("posture-va2")
                .long("posture-va2")
                .help("Include VA2 behavioral profiling in posture report (requires consent)")
                .action(clap::ArgAction::SetTrue)
                .requires("posture"),
        )
        .arg(
            Arg::new("posture-json")
                .long("posture-json")
                .help("Output posture report as JSON")
                .action(clap::ArgAction::SetTrue)
                .requires("posture"),
        )
        .arg(
            Arg::new("va")
                .long("va")
                .help("Run Virtual Adversary effectiveness validation (requires consent)")
                .value_name("URL")
                .num_args(1),
        )
        .arg(
            Arg::new("perf-report")
                .long("perf-report")
                .help("Write current performance snapshot (p95/p99) to JSON file")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("va-replay-run")
                .long("va-replay-run")
                .help("Run a saved VA replay plan from a JSON report")
                .value_name("FILE")
                .num_args(1),
        )
        .arg(
            Arg::new("va-replay-target")
                .long("va-replay-target")
                .help("Override target URL for replay run")
                .value_name("URL")
                .num_args(1),
        )
        .arg(
            Arg::new("va-schema")
                .long("va-schema")
                .help("Print VA report JSON schema")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("va-dry-run")
                .long("va-dry-run")
                .help("Print planned VA payloads without executing")
                .action(clap::ArgAction::SetTrue)
                .requires("va"),
        )
        .arg(
            Arg::new("va-top")
                .long("va-top")
                .help("Number of VA results to print")
                .value_name("COUNT")
                .value_parser(clap::value_parser!(u8))
                .default_value("3")
                .requires("va"),
        )
        .arg(
            Arg::new("va-reason-level")
                .long("va-reason-level")
                .help("VA reason verbosity (0=none, 1=default)")
                .value_name("LEVEL")
                .value_parser(clap::value_parser!(u8))
                .default_value("1")
                .requires("va"),
        )
        .arg(
            Arg::new("va-max-len")
                .long("va-max-len")
                .help("Max payload length to print in VA output")
                .value_name("LEN")
                .value_parser(clap::value_parser!(u16))
                .default_value("80")
                .requires("va"),
        )
        .arg(
            Arg::new("va-output")
                .long("va-output")
                .help("Write VA report JSON and summary to file")
                .value_name("FILE")
                .requires("va"),
        )
        .arg(
            Arg::new("va-json")
                .long("va-json")
                .help("Print VA report JSON to stdout")
                .action(clap::ArgAction::SetTrue)
                .requires("va"),
        )
        .arg(
            Arg::new("va-replay")
                .long("va-replay")
                .help("Print VA replay plan JSON to stdout")
                .action(clap::ArgAction::SetTrue)
                .requires("va"),
        )
        .arg(
            Arg::new("va-replay-csv")
                .long("va-replay-csv")
                .help("Print VA replay plan CSV to stdout")
                .action(clap::ArgAction::SetTrue)
                .requires("va"),
        )
        .arg(
            Arg::new("va-tier")
                .long("va-tier")
                .help("VA safety tier (1-3)")
                .value_name("TIER")
                .value_parser(clap::value_parser!(u8))
                .default_value("1")
                .requires("va"),
        )
        .arg(
            Arg::new("va-budget")
                .long("va-budget")
                .help("VA request budget (max total requests)")
                .value_name("BUDGET")
                .value_parser(clap::value_parser!(u32))
                .default_value("120")
                .requires("va"),
        )
        .arg(
            Arg::new("va-timeout")
                .long("va-timeout")
                .help("VA per-request timeout (seconds)")
                .value_name("SECONDS")
                .value_parser(clap::value_parser!(u64))
                .default_value("15")
                .requires("va"),
        )
        .arg(
            Arg::new("va-delay")
                .long("va-delay")
                .help("VA delay between requests (milliseconds)")
                .value_name("MS")
                .value_parser(clap::value_parser!(u64))
                .default_value("750")
                .requires("va"),
        )
        .arg(
            Arg::new("va-variants")
                .long("va-variants")
                .help("VA max variants per payload")
                .value_name("COUNT")
                .value_parser(clap::value_parser!(u8))
                .default_value("4")
                .requires("va"),
        )
}

// Backward compatibility aliases
pub use build_simple_cli as build_cli;
pub use SimpleCliApp as CliApp;
