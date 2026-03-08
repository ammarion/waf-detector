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
use clap::{Arg, ArgGroup, ArgMatches, Command};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;
use url::Url;

mod benchmark;
pub use benchmark::BenchmarkReport;
use benchmark::{BenchmarkMode, BenchmarkOptions};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Json,
    Ndjson,
    Yaml,
    Compact,
    Table,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorCheck {
    name: String,
    status: DoctorStatus,
    message: String,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorReport {
    ok: bool,
    warning_count: usize,
    failure_count: usize,
    checks: Vec<DoctorCheck>,
}

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

fn truncate_with_ellipsis(value: &str, max_chars: usize) -> String {
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

fn completion_subcommands() -> &'static [&'static str] {
    &[
        "scan",
        "va",
        "va2",
        "benchmark",
        "providers",
        "doctor",
        "completions",
    ]
}

fn completion_global_options() -> &'static [&'static str] {
    &[
        "-h",
        "--help",
        "-V",
        "--version",
        "--perf-report",
        // Legacy root-mode compatibility flags
        "--stdin",
        "--json",
        "--ndjson",
        "--yaml",
        "-c",
        "--compact",
        "-d",
        "--debug",
        "-v",
        "--verbose",
        "--fail-on-error",
        "--payload-analysis",
        "--list",
        "--smoke-test",
        "-o",
        "--output",
        "-H",
        "--header",
        "--aggressive",
        "--benchmark",
        "--benchmark-output",
        "--benchmark-workers",
        "--benchmark-mode",
        "--benchmark-fixtures",
        "--consent",
        "--effectiveness",
        "--effectiveness-config",
        "--effectiveness-similarity-threshold",
        "--effectiveness-reduction-ratio",
        "--effectiveness-min-length-diff",
        "--va2",
        "--va2-dry-run",
        "--va2-run",
        "--va2-json",
        "--va2-output",
        "--va2-phases",
        "--va2-seed",
        "--va2-budget",
        "--posture",
        "--posture-summary",
        "--posture-va2",
        "--posture-json",
        "--va",
        "--va-replay-run",
        "--va-replay-target",
        "--va-schema",
        "--va-dry-run",
        "--va-top",
        "--va-reason-level",
        "--va-max-len",
        "--va-output",
        "--va-json",
        "--va-replay",
        "--va-replay-csv",
        "--va-tier",
        "--va-budget",
        "--va-timeout",
        "--va-delay",
        "--va-variants",
    ]
}

fn completion_scan_options() -> &'static [&'static str] {
    &[
        "--stdin",
        "--json",
        "--ndjson",
        "--yaml",
        "-c",
        "--compact",
        "-d",
        "--debug",
        "-v",
        "--verbose",
        "--fail-on-error",
        "--payload-analysis",
        "--perf-report",
        "-h",
        "--help",
    ]
}

fn completion_va_options() -> &'static [&'static str] {
    &[
        "--dry-run",
        "--json",
        "--replay",
        "--replay-csv",
        "--output",
        "--top",
        "--reason-level",
        "--max-len",
        "--tier",
        "--budget",
        "--timeout",
        "--delay",
        "--variants",
        "--perf-report",
        "-h",
        "--help",
    ]
}

fn completion_va2_options() -> &'static [&'static str] {
    &[
        "--run",
        "--json",
        "--output",
        "--phases",
        "--seed",
        "--budget",
        "--perf-report",
        "-h",
        "--help",
    ]
}

fn completion_benchmark_options() -> &'static [&'static str] {
    &[
        "--output",
        "--workers",
        "--mode",
        "--fixtures",
        "--perf-report",
        "-h",
        "--help",
    ]
}

fn completion_doctor_options() -> &'static [&'static str] {
    &["--json", "--strict", "--perf-report", "-h", "--help"]
}

fn completion_completions_options() -> &'static [&'static str] {
    &["--output", "--perf-report", "-h", "--help"]
}

fn render_bash_completion() -> String {
    let subs = completion_subcommands().join(" ");
    let globals = completion_global_options().join(" ");
    let scan_opts = completion_scan_options().join(" ");
    let va_opts = completion_va_options().join(" ");
    let va2_opts = completion_va2_options().join(" ");
    let benchmark_opts = completion_benchmark_options().join(" ");
    let doctor_opts = completion_doctor_options().join(" ");
    let completions_opts = completion_completions_options().join(" ");

    format!(
        r#"_waf_detect_complete() {{
  local cur prev words cword
  COMPREPLY=()
  cur="${{COMP_WORDS[COMP_CWORD]}}"
  prev="${{COMP_WORDS[COMP_CWORD-1]}}"

  local subcommands="{subs}"
  local global_opts="{globals}"

  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=( $(compgen -W "$subcommands $global_opts" -- "$cur") )
    return 0
  fi

  local cmd="${{COMP_WORDS[1]}}"
  local opts=""
    case "$cmd" in
      scan) opts="{scan_opts}" ;;
      va) opts="{va_opts}" ;;
      va2) opts="{va2_opts}" ;;
      benchmark) opts="{benchmark_opts}" ;;
      providers) opts="--perf-report -h --help" ;;
      doctor) opts="{doctor_opts}" ;;
    completions) opts="{completions_opts}" ;;
    *) opts="$global_opts" ;;
  esac

  COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
}}
complete -F _waf_detect_complete waf-detect
"#
    )
}

fn render_zsh_completion() -> String {
    let subs = completion_subcommands().join(" ");
    let scan_opts = completion_scan_options().join(" ");
    let va_opts = completion_va_options().join(" ");
    let va2_opts = completion_va2_options().join(" ");
    let benchmark_opts = completion_benchmark_options().join(" ");
    let doctor_opts = completion_doctor_options().join(" ");
    let completions_opts = completion_completions_options().join(" ");
    let global_opts = completion_global_options().join(" ");

    format!(
        r#"#compdef waf-detect

_waf_detect() {{
  local -a subcommands
  subcommands=({subs})

  if (( CURRENT == 2 )); then
    _describe 'subcommand' subcommands
    _describe 'option' ({global_opts})
    return
  fi

  local cmd=${{words[2]}}
  local -a opts
    case "$cmd" in
      scan) opts=({scan_opts}) ;;
      va) opts=({va_opts}) ;;
      va2) opts=({va2_opts}) ;;
      benchmark) opts=({benchmark_opts}) ;;
      providers) opts=(--perf-report -h --help) ;;
      doctor) opts=({doctor_opts}) ;;
    completions) opts=({completions_opts}) ;;
    *) opts=({global_opts}) ;;
  esac
  _describe 'option' opts
}}

compdef _waf_detect waf-detect
"#
    )
}

fn render_fish_completion() -> String {
    let mut lines = Vec::new();
    lines.push("complete -c waf-detect -f".to_string());

    for sub in completion_subcommands() {
        lines.push(format!(
            "complete -c waf-detect -n \"__fish_use_subcommand\" -a \"{sub}\""
        ));
    }

    for option in completion_global_options() {
        if let Some(long) = option.strip_prefix("--") {
            lines.push(format!(
                "complete -c waf-detect -n \"__fish_use_subcommand\" -l \"{long}\""
            ));
        } else if let Some(short) = option.strip_prefix('-') {
            if short.len() == 1 {
                lines.push(format!(
                    "complete -c waf-detect -n \"__fish_use_subcommand\" -s \"{short}\""
                ));
            }
        }
    }

    let per_cmd = [
        ("scan", completion_scan_options()),
        ("va", completion_va_options()),
        ("va2", completion_va2_options()),
        ("benchmark", completion_benchmark_options()),
        ("providers", &["--perf-report", "-h", "--help"][..]),
        ("doctor", completion_doctor_options()),
        ("completions", completion_completions_options()),
    ];

    for (cmd, opts) in per_cmd {
        for option in opts {
            if let Some(long) = option.strip_prefix("--") {
                lines.push(format!(
                    "complete -c waf-detect -n \"__fish_seen_subcommand_from {cmd}\" -l \"{long}\""
                ));
            } else if let Some(short) = option.strip_prefix('-') {
                if short.len() == 1 {
                    lines.push(format!(
                        "complete -c waf-detect -n \"__fish_seen_subcommand_from {cmd}\" -s \"{short}\""
                    ));
                }
            }
        }
    }

    lines.join("\n") + "\n"
}

fn feature_enabled(env_key: &str) -> bool {
    std::env::var(env_key)
        .map(|value| {
            let trimmed = value.trim().to_lowercase();
            trimmed == "1" || trimmed == "true" || trimmed == "yes" || trimmed == "on"
        })
        .unwrap_or(false)
}

fn waf_detector_home() -> PathBuf {
    match std::env::var("WAF_DETECTOR_HOME") {
        Ok(path) => PathBuf::from(path),
        Err(_) => dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")),
    }
}

fn binary_on_path(binary: &str) -> bool {
    let path_var = match std::env::var_os("PATH") {
        Some(path) => path,
        None => return false,
    };

    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(binary);
        if candidate.is_file() {
            return true;
        }
    }
    false
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

        if let Some((subcommand, sub_matches)) = matches.subcommand() {
            self.validate_subcommand_root_flags(&matches)?;
            return self.run_subcommand(subcommand, sub_matches).await;
        }

        self.validate_matches(&matches)?;

        let payload_analysis_enabled = matches.get_flag("payload-analysis");
        self.registry
            .set_payload_analysis_enabled(payload_analysis_enabled);
        let engine = DetectionEngine::new(self.registry.clone())?.with_waf_mode_detection();

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
                    println!("  Protection: {:.0}/100 ({})", beh.pmi_score, beh.pmi_label);
                }
                if let Some(enf) = &posture.enforcement {
                    println!(
                        "  Enforce:    {} ({:.0}%)",
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
            let normalized = self.normalize_url(url)?;
            let phases_raw = matches
                .get_one::<String>("va2-phases")
                .map(String::as_str)
                .unwrap_or("baseline,protocol-variance");
            let phases = parse_va2_phases(phases_raw)?;
            let config = Va2CampaignConfig {
                seed: *matches.get_one::<u64>("va2-seed").unwrap_or(&1337),
                budget: *matches.get_one::<u32>("va2-budget").unwrap_or(&60),
            };
            let plan = build_va2_campaign_plan(&normalized, &phases, config)?;

            if matches.get_flag("va2-run") {
                let runner = Va2Runner::new()?;
                let report = runner.run_plan(plan).await?;

                if matches.get_flag("va2-json") {
                    let json = serde_json::to_string_pretty(&report)?;
                    println!("{json}");
                    self.write_perf_report_if_requested(&matches)?;
                    return Ok(());
                }

                if let Some(output) = matches.get_one::<String>("va2-output") {
                    let json = serde_json::to_string_pretty(&report)?;
                    fs::write(output, &json)?;
                    println!("📄 Behavioral analysis report saved to: {output}");
                    self.write_perf_report_if_requested(&matches)?;
                    return Ok(());
                }

                let errors = report
                    .results
                    .iter()
                    .filter(|result| result.error.is_some())
                    .count();
                println!(
                    "🧪 Behavioral Analysis: {} steps | errors {}",
                    report.results.len(),
                    errors
                );
                if let Some(cc) = &report.channel_coverage {
                    println!("\nChannel Inspection:");
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
                            " [UNPROTECTED]"
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
                println!("📄 Behavioral analysis plan saved to: {output}");
                self.write_perf_report_if_requested(&matches)?;
                return Ok(());
            }

            println!(
                "🧭 Behavioral Analysis Dry Run: {} steps across {} phases (seed={}, budget={})",
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
                    serde_json::from_str::<crate::virtual_adversary::report_store::VaStoredReport>(
                        &raw,
                    )
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
                let mut summary = format!(
                    "target={}\nconfidence={:.2}\nrisk={}\nblocked={}\nchallenge={}\nallowed={}\nerror={}\n",
                    report.target_url,
                    report.summary.confidence_score(),
                    report.summary.risk_label(),
                    report.summary.blocked,
                    report.summary.challenge,
                    report.summary.allowed,
                    report.summary.error
                );
                if let Some(reason) = &report.degraded_reason {
                    summary.push_str(&format!("degraded_reason={reason}\n"));
                }
                std::fs::write(&summary_path, summary)?;
                println!("📄 Enforcement replay report saved to: {output}");
                println!("📄 Enforcement replay summary saved to: {summary_path}");
                self.write_perf_report_if_requested(&matches)?;
                return Ok(());
            }
            println!(
                "🧪 Enforcement Replay: {} | Total: {} | Blocked: {} | Challenge: {} | Allowed: {} | Error: {} | Confidence: {:.2} | Risk: {} | Enforcement: {:?} | Evidence: {:.2}",
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
            if let Some(reason) = &report.degraded_reason {
                println!("   Caveat: degraded run ({reason})");
            }
            let max_results = *matches.get_one::<u8>("va-top").unwrap_or(&3) as usize;
            if !report.results.is_empty() {
                println!("   Top Results:");
                let reason_level = *matches.get_one::<u8>("va-reason-level").unwrap_or(&1);
                let max_len = *matches.get_one::<u16>("va-max-len").unwrap_or(&80) as usize;
                for result in report.results.iter().take(max_results) {
                    let payload = truncate_with_ellipsis(&result.payload, max_len);
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
            let normalized = self.normalize_url(url)?;
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
                let plan = runner.plan(&normalized);
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
            let report = runner.run(&normalized)?;
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
                let mut summary = format!(
                    "target={}\nconfidence={:.2}\nrisk={}\nblocked={}\nchallenge={}\nallowed={}\nerror={}\n",
                    report.target_url,
                    report.summary.confidence_score(),
                    report.summary.risk_label(),
                    report.summary.blocked,
                    report.summary.challenge,
                    report.summary.allowed,
                    report.summary.error
                );
                if let Some(reason) = &report.degraded_reason {
                    summary.push_str(&format!("degraded_reason={reason}\n"));
                }
                std::fs::write(&summary_path, summary)?;
                println!("📄 Enforcement report saved to: {output}");
                println!("📄 Enforcement summary saved to: {summary_path}");
                self.write_perf_report_if_requested(&matches)?;
                return Ok(());
            }
            println!(
                "🧪 Enforcement Test: {} | Total: {} | Blocked: {} | Challenge: {} | Allowed: {} | Error: {} | Confidence: {:.2} | Risk: {} | Enforcement: {:?} | Evidence: {:.2}",
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
            if let Some(reason) = &report.degraded_reason {
                println!("   Caveat: degraded run ({reason})");
            }
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
                    let payload = truncate_with_ellipsis(&result.payload, max_len);
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
        let result = self.run_scan_mode(&engine, &matches).await;
        self.write_perf_report_if_requested(&matches)?;
        result
    }

    fn validate_subcommand_root_flags(&self, matches: &ArgMatches) -> Result<()> {
        let mut incompatible = Vec::new();
        if matches.get_many::<String>("targets").is_some() {
            incompatible.push("TARGET");
        }

        let root_flags = [
            ("--stdin", matches.get_flag("stdin")),
            ("--json", matches.get_flag("json")),
            ("--ndjson", matches.get_flag("ndjson")),
            ("--yaml", matches.get_flag("yaml")),
            ("--compact", matches.get_flag("compact")),
            ("--debug", matches.get_flag("debug")),
            ("--verbose", matches.get_flag("verbose")),
            ("--fail-on-error", matches.get_flag("fail-on-error")),
            ("--payload-analysis", matches.get_flag("payload-analysis")),
            ("--list", matches.get_flag("list")),
            ("--smoke-test", matches.get_flag("smoke-test")),
            ("--va-schema", matches.get_flag("va-schema")),
            ("--consent", matches.get_many::<String>("consent").is_some()),
            (
                "--benchmark",
                matches.get_one::<String>("benchmark").is_some(),
            ),
            (
                "--effectiveness",
                matches.get_one::<String>("effectiveness").is_some(),
            ),
            ("--posture", matches.get_one::<String>("posture").is_some()),
            (
                "--posture-summary",
                matches.get_one::<String>("posture-summary").is_some(),
            ),
            ("--va2", matches.get_one::<String>("va2").is_some()),
            ("--va", matches.get_one::<String>("va").is_some()),
            (
                "--va-replay-run",
                matches.get_one::<String>("va-replay-run").is_some(),
            ),
        ];

        for (flag, enabled) in root_flags {
            if enabled {
                incompatible.push(flag);
            }
        }

        if !incompatible.is_empty() {
            return Err(anyhow!(
                "Do not mix legacy root flags with subcommands. Move these after the subcommand: {}",
                incompatible.join(", ")
            ));
        }

        Ok(())
    }

    fn build_engine(&self, payload_analysis_enabled: bool) -> Result<DetectionEngine> {
        self.registry
            .set_payload_analysis_enabled(payload_analysis_enabled);
        Ok(DetectionEngine::new(self.registry.clone())?.with_waf_mode_detection())
    }

    async fn run_subcommand(&self, subcommand: &str, matches: &ArgMatches) -> Result<()> {
        match subcommand {
            "scan" => {
                self.validate_scan_matches(matches)?;
                let engine = self.build_engine(matches.get_flag("payload-analysis"))?;
                let result = self.run_scan_mode(&engine, matches).await;
                self.write_perf_report_if_requested(matches)?;
                result
            }
            "providers" => {
                let engine = self.build_engine(false)?;
                self.list_providers(&engine).await
            }
            "benchmark" => {
                let engine = self.build_engine(false)?;
                let corpus = matches
                    .get_one::<String>("benchmark")
                    .ok_or_else(|| anyhow!("benchmark requires a corpus path"))?;
                let result = self.run_benchmark(&engine, corpus, matches).await;
                self.write_perf_report_if_requested(matches)?;
                result
            }
            "va" => {
                let result = self.run_va_subcommand(matches).await;
                self.write_perf_report_if_requested(matches)?;
                result
            }
            "va2" => {
                let result = self.run_va2_subcommand(matches).await;
                self.write_perf_report_if_requested(matches)?;
                result
            }
            "doctor" => {
                let result = self.run_doctor_subcommand(matches).await;
                self.write_perf_report_if_requested(matches)?;
                result
            }
            "completions" => {
                self.run_completions_subcommand(matches)?;
                self.write_perf_report_if_requested(matches)?;
                Ok(())
            }
            other => Err(anyhow!("Unknown subcommand: {other}")),
        }
    }

    fn validate_scan_matches(&self, matches: &ArgMatches) -> Result<()> {
        let machine_output =
            matches.get_flag("json") || matches.get_flag("yaml") || matches.get_flag("ndjson");
        if matches.get_flag("verbose") && machine_output {
            return Err(anyhow!(
                "--verbose cannot be combined with --json, --yaml, or --ndjson."
            ));
        }

        if matches.get_flag("debug")
            && (matches.get_flag("json")
                || matches.get_flag("yaml")
                || matches.get_flag("compact")
                || matches.get_flag("ndjson"))
        {
            return Err(anyhow!(
                "--debug is only supported with the default table output format."
            ));
        }

        Ok(())
    }

    async fn run_scan_mode(&self, engine: &DetectionEngine, matches: &ArgMatches) -> Result<()> {
        let targets = self.parse_targets(matches)?;

        if targets.is_empty() {
            return Err(anyhow!(
                "No targets specified. Provide TARGET args, @file input, or --stdin."
            ));
        }

        // Determine output format
        let format = self.determine_format(matches);
        let debug = matches.get_flag("debug");
        let verbose = matches.get_flag("verbose");
        let fail_on_error = matches.get_flag("fail-on-error");

        // Scan targets
        if targets.len() == 1 {
            self.scan_single(engine, &targets[0], &format, debug, verbose)
                .await
        } else {
            self.scan_batch(engine, &targets, &format, debug, verbose, fail_on_error)
                .await
        }
    }

    async fn run_va_subcommand(&self, matches: &ArgMatches) -> Result<()> {
        let target = matches
            .get_one::<String>("target")
            .ok_or_else(|| anyhow!("va requires a target URL"))?;
        let normalized = self.normalize_url(target)?;

        let config = VirtualAdversaryConfig {
            tier: *matches.get_one::<u8>("tier").unwrap_or(&1),
            request_budget: *matches.get_one::<u32>("budget").unwrap_or(&120),
            request_timeout: std::time::Duration::from_secs(
                *matches.get_one::<u64>("timeout").unwrap_or(&15),
            ),
            request_delay: std::time::Duration::from_millis(
                *matches.get_one::<u64>("delay").unwrap_or(&750),
            ),
            max_variants_per_payload: *matches.get_one::<u8>("variants").unwrap_or(&4),
            skip_dns_validation: false,
        };

        let mut runner = VirtualAdversaryRunner::new(config)?;
        if matches.get_flag("dry-run") {
            let plan = runner.plan(&normalized);
            println!("🧪 VA Dry Run: {} planned probes", plan.len());
            for probe in plan {
                println!(
                    " - {:?}::{:?}: {}",
                    probe.probe.class, probe.probe.channel, probe.display
                );
            }
            return Ok(());
        }

        let report = runner.run(&normalized)?;
        if matches.get_flag("json") {
            let json = serde_json::to_string_pretty(&report)?;
            println!("{json}");
            return Ok(());
        }
        if matches.get_flag("replay") {
            let json = serde_json::to_string_pretty(&report.replay_plan)?;
            println!("{json}");
            return Ok(());
        }
        if matches.get_flag("replay-csv") {
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
            return Ok(());
        }
        if let Some(output) = matches.get_one::<String>("output") {
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
            println!("📄 Enforcement report saved to: {output}");
            println!("📄 Enforcement summary saved to: {summary_path}");
            return Ok(());
        }
        println!(
            "🧪 Enforcement Test: {} | Total: {} | Blocked: {} | Challenge: {} | Allowed: {} | Error: {} | Confidence: {:.2} | Risk: {} | Enforcement: {:?} | Evidence: {:.2}",
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
        let max_results = *matches.get_one::<u8>("top").unwrap_or(&3) as usize;
        if !report.results.is_empty() {
            println!("   Top Results:");
            let reason_level = *matches.get_one::<u8>("reason-level").unwrap_or(&1);
            let max_len = *matches.get_one::<u16>("max-len").unwrap_or(&80) as usize;
            for result in report.results.iter().take(max_results) {
                let payload = truncate_with_ellipsis(&result.payload, max_len);
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

        Ok(())
    }

    async fn run_va2_subcommand(&self, matches: &ArgMatches) -> Result<()> {
        let target = matches
            .get_one::<String>("target")
            .ok_or_else(|| anyhow!("va2 requires a target URL"))?;
        let normalized = self.normalize_url(target)?;

        let phases_raw = matches
            .get_one::<String>("phases")
            .map(String::as_str)
            .unwrap_or("baseline,protocol-variance");
        let phases = parse_va2_phases(phases_raw)?;
        let config = Va2CampaignConfig {
            seed: *matches.get_one::<u64>("seed").unwrap_or(&1337),
            budget: *matches.get_one::<u32>("budget").unwrap_or(&60),
        };
        let plan = build_va2_campaign_plan(&normalized, &phases, config)?;

        if matches.get_flag("run") {
            let runner = Va2Runner::new()?;
            let report = runner.run_plan(plan).await?;

            if matches.get_flag("json") {
                let json = serde_json::to_string_pretty(&report)?;
                println!("{json}");
                return Ok(());
            }

            if let Some(output) = matches.get_one::<String>("output") {
                let json = serde_json::to_string_pretty(&report)?;
                fs::write(output, &json)?;
                println!("📄 Behavioral analysis report saved to: {output}");
                return Ok(());
            }

            let errors = report
                .results
                .iter()
                .filter(|result| result.error.is_some())
                .count();
            println!(
                "🧪 Behavioral Analysis: {} steps | errors {}",
                report.results.len(),
                errors
            );
            if let Some(cc) = &report.channel_coverage {
                println!("\nChannel Inspection:");
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
                        " [UNPROTECTED]"
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
            return Ok(());
        }

        if matches.get_flag("json") {
            let json = serde_json::to_string_pretty(&plan)?;
            println!("{json}");
            return Ok(());
        }

        if let Some(output) = matches.get_one::<String>("output") {
            let json = serde_json::to_string_pretty(&plan)?;
            fs::write(output, json)?;
            println!("📄 Behavioral analysis plan saved to: {output}");
            return Ok(());
        }

        println!(
            "🧭 Behavioral Analysis Dry Run: {} steps across {} phases (seed={}, budget={})",
            plan.steps.len(),
            plan.phases.len(),
            plan.seed,
            plan.budget
        );
        Ok(())
    }

    async fn run_doctor_subcommand(&self, matches: &ArgMatches) -> Result<()> {
        let as_json = matches.get_flag("json");
        let strict = matches.get_flag("strict");
        let original_no_proxy = std::env::var_os("WAF_DETECTOR_NO_PROXY");
        if original_no_proxy.is_none() {
            std::env::set_var("WAF_DETECTOR_NO_PROXY", "1");
        }
        let mut checks: Vec<DoctorCheck> = Vec::new();

        let mut push_check = |name: &str, status: DoctorStatus, message: String| {
            checks.push(DoctorCheck {
                name: name.to_string(),
                status,
                message,
            });
        };

        match std::env::current_exe() {
            Ok(path) => {
                push_check(
                    "binary_location",
                    DoctorStatus::Pass,
                    format!("running as {}", path.display()),
                );
            }
            Err(err) => {
                push_check(
                    "binary_location",
                    DoctorStatus::Warn,
                    format!("unable to resolve current executable path: {err}"),
                );
            }
        }

        if binary_on_path("waf-detect") {
            push_check(
                "path_lookup",
                DoctorStatus::Pass,
                "waf-detect found on PATH".to_string(),
            );
        } else {
            push_check(
                "path_lookup",
                DoctorStatus::Warn,
                "waf-detect not found on PATH (shell completion install may need full path)"
                    .to_string(),
            );
        }

        let shell = std::env::var("SHELL").unwrap_or_else(|_| "unknown".to_string());
        if shell == "unknown" {
            push_check(
                "shell_env",
                DoctorStatus::Warn,
                "SHELL environment variable is not set".to_string(),
            );
        } else {
            push_check("shell_env", DoctorStatus::Pass, format!("SHELL={shell}"));
        }

        let home_dir = waf_detector_home();
        let home_writable = (|| -> Result<()> {
            fs::create_dir_all(&home_dir)?;
            let probe = home_dir.join(".waf-detector-doctor-write-test");
            let mut file = fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&probe)?;
            file.write_all(b"ok")?;
            drop(file);
            let _ = fs::remove_file(&probe);
            Ok(())
        })();
        match home_writable {
            Ok(()) => push_check(
                "home_dir",
                DoctorStatus::Pass,
                format!("writable home directory: {}", home_dir.display()),
            ),
            Err(err) => push_check(
                "home_dir",
                DoctorStatus::Warn,
                format!(
                    "cannot write under {}: {err} (set WAF_DETECTOR_HOME to a writable path)",
                    home_dir.display()
                ),
            ),
        }

        let consent_manager = crate::effectiveness::consent::ConsentManager::new();
        match consent_manager.status() {
            Ok(status) => {
                if status.has_consent {
                    push_check(
                        "consent_status",
                        DoctorStatus::Pass,
                        format!(
                            "valid consent (targets={}, expires_in_days={})",
                            status.authorized_targets.len(),
                            status.expires_in_days.unwrap_or_default()
                        ),
                    );
                } else {
                    push_check(
                        "consent_status",
                        DoctorStatus::Warn,
                        "no valid consent on file (required for enforcement/behavioral/effectiveness tests)"
                            .to_string(),
                    );
                }
            }
            Err(err) => push_check(
                "consent_status",
                DoctorStatus::Fail,
                format!("failed to load consent status: {err}"),
            ),
        }

        if std::env::var("WAF_DETECTOR_INSECURE_TLS").is_ok() {
            push_check(
                "tls_mode",
                DoctorStatus::Warn,
                "WAF_DETECTOR_INSECURE_TLS is enabled (certificate validation disabled)"
                    .to_string(),
            );
        } else {
            push_check(
                "tls_mode",
                DoctorStatus::Pass,
                "TLS certificate validation is enabled".to_string(),
            );
        }

        let api_token_present = std::env::var("WAF_DETECTOR_API_TOKEN")
            .map(|token| !token.trim().is_empty())
            .unwrap_or(false);
        if api_token_present {
            push_check(
                "api_token",
                DoctorStatus::Pass,
                "WAF_DETECTOR_API_TOKEN is configured".to_string(),
            );
        } else {
            push_check(
                "api_token",
                DoctorStatus::Warn,
                "WAF_DETECTOR_API_TOKEN is not set (API auth disabled)".to_string(),
            );
        }

        match crate::http::HttpClient::new() {
            Ok(_) => push_check(
                "http_client",
                DoctorStatus::Pass,
                "HTTP client initialization succeeded".to_string(),
            ),
            Err(err) => push_check(
                "http_client",
                DoctorStatus::Fail,
                format!("HTTP client initialization failed: {err}"),
            ),
        }

        match crate::dns::optimized::DnsResolver::new() {
            Ok(_) => push_check(
                "dns_resolver",
                DoctorStatus::Pass,
                "DNS resolver initialization succeeded".to_string(),
            ),
            Err(err) => push_check(
                "dns_resolver",
                DoctorStatus::Fail,
                format!("DNS resolver initialization failed: {err}"),
            ),
        }

        match self.build_engine(false) {
            Ok(engine) => push_check(
                "providers",
                DoctorStatus::Pass,
                format!("{} detection providers loaded", engine.get_provider_count()),
            ),
            Err(err) => push_check(
                "providers",
                DoctorStatus::Fail,
                format!("failed to initialize detection engine: {err}"),
            ),
        }

        let failure_count = checks
            .iter()
            .filter(|check| check.status == DoctorStatus::Fail)
            .count();
        let warning_count = checks
            .iter()
            .filter(|check| check.status == DoctorStatus::Warn)
            .count();
        let ok = failure_count == 0 && (!strict || warning_count == 0);
        let report = DoctorReport {
            ok,
            warning_count,
            failure_count,
            checks,
        };

        if as_json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            println!("WAF Detector Doctor");
            println!("──────────────────");
            for check in &report.checks {
                let label = match check.status {
                    DoctorStatus::Pass => "PASS",
                    DoctorStatus::Warn => "WARN",
                    DoctorStatus::Fail => "FAIL",
                };
                println!("[{label}] {:<16} {}", check.name, check.message);
            }
            println!();
            println!(
                "Summary: ok={} warnings={} failures={} strict={}",
                report.ok, report.warning_count, report.failure_count, strict
            );
        }

        if report.failure_count > 0 {
            if let Some(value) = &original_no_proxy {
                std::env::set_var("WAF_DETECTOR_NO_PROXY", value);
            } else {
                std::env::remove_var("WAF_DETECTOR_NO_PROXY");
            }
            return Err(anyhow!(
                "doctor found {} failing check(s)",
                report.failure_count
            ));
        }
        if strict && report.warning_count > 0 {
            if let Some(value) = &original_no_proxy {
                std::env::set_var("WAF_DETECTOR_NO_PROXY", value);
            } else {
                std::env::remove_var("WAF_DETECTOR_NO_PROXY");
            }
            return Err(anyhow!(
                "doctor strict mode failed due to {} warning(s)",
                report.warning_count
            ));
        }

        if let Some(value) = &original_no_proxy {
            std::env::set_var("WAF_DETECTOR_NO_PROXY", value);
        } else {
            std::env::remove_var("WAF_DETECTOR_NO_PROXY");
        }

        Ok(())
    }

    fn run_completions_subcommand(&self, matches: &ArgMatches) -> Result<()> {
        run_completions_command(matches)
    }

    fn validate_matches(&self, matches: &ArgMatches) -> Result<()> {
        let modes = [
            ("--list", matches.get_flag("list")),
            ("--consent", matches.get_many::<String>("consent").is_some()),
            (
                "--benchmark",
                matches.get_one::<String>("benchmark").is_some(),
            ),
            (
                "--effectiveness",
                matches.get_one::<String>("effectiveness").is_some(),
            ),
            ("--smoke-test", matches.get_flag("smoke-test")),
            ("--va-schema", matches.get_flag("va-schema")),
            ("--posture", matches.get_one::<String>("posture").is_some()),
            (
                "--posture-summary",
                matches.get_one::<String>("posture-summary").is_some(),
            ),
            ("--va2", matches.get_one::<String>("va2").is_some()),
            ("--va", matches.get_one::<String>("va").is_some()),
            (
                "--va-replay-run",
                matches.get_one::<String>("va-replay-run").is_some(),
            ),
        ];

        let active_modes: Vec<&str> = modes
            .iter()
            .filter(|(_, active)| *active)
            .map(|(name, _)| *name)
            .collect();

        if active_modes.len() > 1 {
            return Err(anyhow!(
                "Conflicting modes selected: {}. Choose exactly one execution mode.",
                active_modes.join(", ")
            ));
        }

        let is_smoke_test = matches.get_flag("smoke-test");
        let target_count = matches
            .get_many::<String>("targets")
            .map(|items| items.len())
            .unwrap_or(0);

        if target_count > 0 && !active_modes.is_empty() && !is_smoke_test {
            return Err(anyhow!(
                "Positional TARGET arguments are only valid for default scan mode and --smoke-test."
            ));
        }

        if is_smoke_test && target_count != 1 {
            return Err(anyhow!(
                "--smoke-test requires exactly one TARGET argument."
            ));
        }

        let machine_output =
            matches.get_flag("json") || matches.get_flag("yaml") || matches.get_flag("ndjson");
        if matches.get_flag("verbose") && machine_output {
            return Err(anyhow!(
                "--verbose cannot be combined with --json, --yaml, or --ndjson."
            ));
        }

        if matches.get_flag("debug")
            && (matches.get_flag("json")
                || matches.get_flag("yaml")
                || matches.get_flag("compact")
                || matches.get_flag("ndjson"))
        {
            return Err(anyhow!(
                "--debug is only supported with the default table output format."
            ));
        }

        let scan_only_flags = [
            ("--json", matches.get_flag("json")),
            ("--yaml", matches.get_flag("yaml")),
            ("--compact", matches.get_flag("compact")),
            ("--ndjson", matches.get_flag("ndjson")),
            ("--debug", matches.get_flag("debug")),
            ("--verbose", matches.get_flag("verbose")),
            ("--payload-analysis", matches.get_flag("payload-analysis")),
            ("--stdin", matches.get_flag("stdin")),
            ("--fail-on-error", matches.get_flag("fail-on-error")),
        ];
        let active_scan_only: Vec<&str> = scan_only_flags
            .iter()
            .filter(|(_, active)| *active)
            .map(|(name, _)| *name)
            .collect();
        if !active_modes.is_empty() && !active_scan_only.is_empty() {
            return Err(anyhow!(
                "Scan-only flags cannot be used with {}: {}",
                active_modes.join(", "),
                active_scan_only.join(", ")
            ));
        }

        Ok(())
    }

    fn parse_targets(&self, matches: &ArgMatches) -> Result<Vec<String>> {
        let mut targets = Vec::new();
        let mut seen = HashSet::new();

        // Get targets from direct arguments
        if let Some(domains) = matches.get_many::<String>("targets") {
            for domain in domains {
                if let Some(filename) = domain.strip_prefix('@') {
                    // File input: @file.txt
                    let content = fs::read_to_string(filename)
                        .map_err(|e| anyhow!("Failed to read file '{}': {}", filename, e))?;

                    for (line_idx, line) in content.lines().enumerate() {
                        let line = line.trim();
                        if line.is_empty() || line.starts_with('#') {
                            continue;
                        }
                        let normalized = self
                            .normalize_url(line)
                            .map_err(|e| anyhow!("{}:{}: {}", filename, line_idx + 1, e))?;
                        if seen.insert(normalized.clone()) {
                            targets.push(normalized);
                        }
                    }
                } else {
                    let normalized = self
                        .normalize_url(domain)
                        .map_err(|e| anyhow!("target '{}': {}", domain, e))?;
                    if seen.insert(normalized.clone()) {
                        targets.push(normalized);
                    }
                }
            }
        }

        if matches.get_flag("stdin") {
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input)?;
            for (line_idx, line) in input.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let normalized = self
                    .normalize_url(line)
                    .map_err(|e| anyhow!("stdin:{}: {}", line_idx + 1, e))?;
                if seen.insert(normalized.clone()) {
                    targets.push(normalized);
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

    fn determine_format(&self, matches: &ArgMatches) -> OutputFormat {
        if matches.get_flag("json") {
            OutputFormat::Json
        } else if matches.get_flag("ndjson") {
            OutputFormat::Ndjson
        } else if matches.get_flag("yaml") {
            OutputFormat::Yaml
        } else if matches.get_flag("compact") {
            OutputFormat::Compact
        } else {
            OutputFormat::Table
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
        format: &OutputFormat,
        debug: bool,
        verbose: bool,
    ) -> Result<()> {
        let human_output = matches!(format, OutputFormat::Table | OutputFormat::Compact);
        if verbose && human_output {
            println!("🔍 Scanning: {url}");
        }

        let start_time = Instant::now();
        let detection_result = engine.detect(url).await?;
        let scan_time = start_time.elapsed();

        match format {
            OutputFormat::Json => {
                println!("{}", serde_json::to_string_pretty(&detection_result)?);
            }
            OutputFormat::Ndjson => {
                println!("{}", serde_json::to_string(&detection_result)?);
            }
            OutputFormat::Yaml => {
                println!("{}", serde_yml::to_string(&detection_result)?);
            }
            OutputFormat::Compact => {
                self.print_compact(&detection_result);
            }
            OutputFormat::Table => {
                self.print_table_format(&detection_result, debug);
            }
        }

        if verbose && human_output {
            println!("⏱️  Scan completed in {:.2}ms", scan_time.as_millis());
        }

        Ok(())
    }

    async fn scan_batch(
        &self,
        engine: &DetectionEngine,
        urls: &[String],
        format: &OutputFormat,
        debug: bool,
        verbose: bool,
        fail_on_error: bool,
    ) -> Result<()> {
        let human_output = matches!(format, OutputFormat::Table | OutputFormat::Compact);
        if verbose && human_output {
            println!("🔍 Scanning {} targets...", urls.len());
        }

        let total_start = Instant::now();

        // Use parallel batch detection with rate limiting (max 3 concurrent requests)
        let url_refs: Vec<&str> = urls.iter().map(|s| s.as_str()).collect();
        let batch_results = engine.detect_batch(&url_refs, 3).await?;

        // Convert HashMap results back to Vec in original order for consistent output
        let mut results = Vec::new();
        for (i, url) in urls.iter().enumerate() {
            if verbose && human_output {
                println!("({}/{}) {} - Processing...", i + 1, urls.len(), url);
            }

            if let Some(result) = batch_results.get(url) {
                results.push(result.clone());
            }
        }

        let total_time = total_start.elapsed();

        match format {
            OutputFormat::Json => {
                println!("{}", serde_json::to_string_pretty(&results)?);
            }
            OutputFormat::Ndjson => {
                for result in &results {
                    println!("{}", serde_json::to_string(result)?);
                }
            }
            OutputFormat::Yaml => {
                println!("{}", serde_yml::to_string(&results)?);
            }
            OutputFormat::Compact => {
                for result in &results {
                    self.print_compact(result);
                }
            }
            OutputFormat::Table => {
                for (i, result) in results.iter().enumerate() {
                    if i > 0 {
                        println!();
                    }
                    self.print_table_format(result, debug);
                }
            }
        }

        let error_count = results
            .iter()
            .filter(|result| result.error.is_some())
            .count();
        if human_output {
            self.print_batch_summary(&results, total_time);
        } else if verbose {
            println!("\n⏱️  Total scan time: {:.2}s", total_time.as_secs_f64());
        }

        if fail_on_error && error_count > 0 {
            return Err(anyhow!(
                "{error_count} target(s) failed detection in batch run (--fail-on-error enabled)"
            ));
        }

        Ok(())
    }

    fn print_batch_summary(&self, results: &[DetectionResult], total_time: std::time::Duration) {
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

    fn print_compact(&self, result: &DetectionResult) {
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
        let url_display = truncate_with_ellipsis(&result.url, 67);
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

pub fn run_completions_command(matches: &ArgMatches) -> Result<()> {
    let shell = matches
        .get_one::<String>("shell")
        .ok_or_else(|| anyhow!("completions requires a shell name"))?;

    let script = match shell.as_str() {
        "bash" => render_bash_completion(),
        "zsh" => render_zsh_completion(),
        "fish" => render_fish_completion(),
        other => {
            return Err(anyhow!(
                "unsupported shell '{other}' (expected bash|zsh|fish)"
            ));
        }
    };

    if let Some(output) = matches.get_one::<String>("output") {
        fs::write(output, &script)?;
        let output_path = PathBuf::from(output);
        let display_path = output_path
            .canonicalize()
            .unwrap_or_else(|_| output_path.clone());
        println!("Completion script written to: {output}");
        println!("Load it with: source {}", display_path.display());
        return Ok(());
    }

    print!("{script}");
    Ok(())
}

fn build_scan_subcommand() -> Command {
    Command::new("scan")
        .about("Scan one or more targets for WAF/CDN detection")
        .arg(
            Arg::new("targets")
                .help("Domain names, URLs, or @file.txt to scan")
                .value_name("TARGET")
                .action(clap::ArgAction::Append)
                .num_args(0..),
        )
        .arg(
            Arg::new("stdin")
                .long("stdin")
                .help("Read newline-delimited targets from stdin (comments with # are ignored)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .help("Output results in JSON format")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("ndjson")
                .long("ndjson")
                .help("Output results as newline-delimited JSON (one result per line)")
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
            Arg::new("fail-on-error")
                .long("fail-on-error")
                .help("Exit non-zero when any target fails in batch scan mode")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("payload-analysis")
                .long("payload-analysis")
                .help("Enable active payload-based probing during detection (authorized targets only)")
                .action(clap::ArgAction::SetTrue),
        )
        .group(
            ArgGroup::new("scan-subcommand-output-format")
                .args(["json", "yaml", "compact", "ndjson"])
                .multiple(false),
        )
}

fn build_providers_subcommand() -> Command {
    Command::new("providers").about("List available detection providers")
}

fn build_benchmark_subcommand() -> Command {
    Command::new("benchmark")
        .about("Run offline detection benchmark against a labeled corpus")
        .arg(
            Arg::new("benchmark")
                .help("Path to benchmark corpus JSON file")
                .value_name("CORPUS")
                .required(true),
        )
        .arg(
            Arg::new("benchmark-output")
                .long("output")
                .help("Save benchmark results as JSON to file")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("benchmark-workers")
                .long("workers")
                .help("Number of concurrent detection workers (default: 3)")
                .value_name("COUNT")
                .value_parser(clap::value_parser!(usize))
                .default_value("3"),
        )
        .arg(
            Arg::new("benchmark-mode")
                .long("mode")
                .help("Benchmark execution mode: live network or fixture replay")
                .value_name("MODE")
                .value_parser(["live", "fixture"])
                .default_value("live"),
        )
        .arg(
            Arg::new("benchmark-fixtures")
                .long("fixtures")
                .help("Directory containing benchmark fixture corpus (fixtures.json)")
                .value_name("DIR"),
        )
}

fn build_va_subcommand() -> Command {
    Command::new("va")
        .about("Run enforcement test — send attack payloads and measure block rates")
        .arg(
            Arg::new("target")
                .help("Target URL or domain")
                .value_name("URL")
                .required(true),
        )
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .help("Print planned enforcement payloads without executing")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .help("Print enforcement report JSON to stdout")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("replay")
                .long("replay")
                .help("Print enforcement replay plan JSON to stdout")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("replay-csv")
                .long("replay-csv")
                .help("Print enforcement replay plan CSV to stdout")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .help("Write enforcement report JSON and summary to file")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("top")
                .long("top")
                .help("Number of enforcement results to print")
                .value_name("COUNT")
                .value_parser(clap::value_parser!(u8))
                .default_value("3"),
        )
        .arg(
            Arg::new("reason-level")
                .long("reason-level")
                .help("Reason verbosity (0=none, 1=default)")
                .value_name("LEVEL")
                .value_parser(clap::value_parser!(u8))
                .default_value("1"),
        )
        .arg(
            Arg::new("max-len")
                .long("max-len")
                .help("Max payload length to print in enforcement output")
                .value_name("LEN")
                .value_parser(clap::value_parser!(u16))
                .default_value("80"),
        )
        .arg(
            Arg::new("tier")
                .long("tier")
                .help("Safety tier (1-3)")
                .value_name("TIER")
                .value_parser(clap::value_parser!(u8))
                .default_value("1"),
        )
        .arg(
            Arg::new("budget")
                .long("budget")
                .help("Request budget (max total requests)")
                .value_name("BUDGET")
                .value_parser(clap::value_parser!(u32))
                .default_value("120"),
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .help("Per-request timeout (seconds)")
                .value_name("SECONDS")
                .value_parser(clap::value_parser!(u64))
                .default_value("15"),
        )
        .arg(
            Arg::new("delay")
                .long("delay")
                .help("Delay between requests (milliseconds)")
                .value_name("MS")
                .value_parser(clap::value_parser!(u64))
                .default_value("750"),
        )
        .arg(
            Arg::new("variants")
                .long("variants")
                .help("VA max variants per payload")
                .value_name("COUNT")
                .value_parser(clap::value_parser!(u8))
                .default_value("4"),
        )
}

fn build_va2_subcommand() -> Command {
    Command::new("va2")
        .about("Run behavioral analysis — paired probes testing WAF sophistication")
        .arg(
            Arg::new("target")
                .help("Target URL or domain")
                .value_name("URL")
                .required(true),
        )
        .arg(
            Arg::new("run")
                .long("run")
                .help("Execute behavioral analysis (requires consent)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .help("Print behavioral analysis plan/report JSON to stdout")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .help("Write behavioral analysis plan/report JSON to file")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("phases")
                .long("phases")
                .help("Analysis phases (comma-separated)")
                .value_name("LIST")
                .default_value("baseline,protocol-variance"),
        )
        .arg(
            Arg::new("seed")
                .long("seed")
                .help("Deterministic seed for reproducible analysis")
                .value_name("SEED")
                .value_parser(clap::value_parser!(u64))
                .default_value("1337"),
        )
        .arg(
            Arg::new("budget")
                .long("budget")
                .help("Request budget for behavioral analysis")
                .value_name("COUNT")
                .value_parser(clap::value_parser!(u32))
                .default_value("60"),
        )
}

fn build_doctor_subcommand() -> Command {
    Command::new("doctor")
        .about("Run environment and runtime health checks")
        .arg(
            Arg::new("json")
                .long("json")
                .help("Output doctor report as JSON")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("strict")
                .long("strict")
                .help("Treat warnings as failures (non-zero exit)")
                .action(clap::ArgAction::SetTrue),
        )
}

fn build_completions_subcommand() -> Command {
    Command::new("completions")
        .about("Generate shell completion scripts")
        .arg(
            Arg::new("shell")
                .help("Shell to generate completions for")
                .value_name("SHELL")
                .value_parser(["bash", "zsh", "fish"])
                .required(true),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .short('o')
                .help("Write completion script to file instead of stdout")
                .value_name("FILE"),
        )
}

pub fn build_simple_cli() -> Command {
    Command::new("waf-detect")
        .version("0.1.0")
        .author("WAF Detector Team")
        .about("WAF/CDN detection CLI with modern subcommands and legacy compatibility")
        .long_about(
            r#"
MODERN COMMANDS (recommended):
  waf-detect scan cloudflare.com
  waf-detect scan @urls.txt --ndjson
  cat urls.txt | waf-detect scan --stdin --compact
  waf-detect va example.com --dry-run
  waf-detect va2 example.com --run --json
  waf-detect benchmark benchmark_corpus.json --workers 8
  waf-detect providers
  waf-detect doctor
  waf-detect completions zsh -o ~/.zsh/completions/_waf-detect

LEGACY FLAG MODE (still supported):
  waf-detect cloudflare.com --json
  waf-detect --va https://example.com
  waf-detect --va2 https://example.com --va2-run

The tool automatically adds https:// for bare domains where supported.
        "#,
        )
        .subcommand(build_scan_subcommand())
        .subcommand(build_va_subcommand())
        .subcommand(build_va2_subcommand())
        .subcommand(build_benchmark_subcommand())
        .subcommand(build_providers_subcommand())
        .subcommand(build_doctor_subcommand())
        .subcommand(build_completions_subcommand())
        .arg(
            Arg::new("targets")
                .help("Domain names, URLs, or @file.txt to scan")
                .value_name("TARGET")
                .action(clap::ArgAction::Append)
                .num_args(0..),
        )
        .arg(
            Arg::new("stdin")
                .long("stdin")
                .help("Read newline-delimited targets from stdin (comments with # are ignored)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .help("Output results in JSON format")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("ndjson")
                .long("ndjson")
                .help("Output results as newline-delimited JSON (one result per line)")
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
            Arg::new("fail-on-error")
                .long("fail-on-error")
                .help("Exit non-zero when any target fails in batch scan mode")
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
                .help("Run behavioral analysis (paired probes testing WAF sophistication)")
                .value_name("URL")
                .num_args(1),
        )
        .arg(
            Arg::new("va2-dry-run")
                .long("va2-dry-run")
                .help("Print behavioral analysis plan without execution")
                .action(clap::ArgAction::SetTrue)
                .requires("va2"),
        )
        .arg(
            Arg::new("va2-run")
                .long("va2-run")
                .help("Execute behavioral analysis (requires consent)")
                .action(clap::ArgAction::SetTrue)
                .requires("va2"),
        )
        .arg(
            Arg::new("va2-json")
                .long("va2-json")
                .help("Print behavioral analysis plan JSON to stdout")
                .action(clap::ArgAction::SetTrue)
                .requires("va2"),
        )
        .arg(
            Arg::new("va2-output")
                .long("va2-output")
                .help("Write behavioral analysis plan JSON to file")
                .value_name("FILE")
                .requires("va2"),
        )
        .arg(
            Arg::new("va2-phases")
                .long("va2-phases")
                .help("Analysis phases (comma-separated)")
                .value_name("LIST")
                .default_value("baseline,protocol-variance")
                .requires("va2"),
        )
        .arg(
            Arg::new("va2-seed")
                .long("va2-seed")
                .help("Deterministic seed for reproducible analysis")
                .value_name("SEED")
                .value_parser(clap::value_parser!(u64))
                .default_value("1337")
                .requires("va2"),
        )
        .arg(
            Arg::new("va2-budget")
                .long("va2-budget")
                .help("Request budget for behavioral analysis")
                .value_name("COUNT")
                .value_parser(clap::value_parser!(u32))
                .default_value("60")
                .requires("va2"),
        )
        .arg(
            Arg::new("posture")
                .long("posture")
                .help("Generate unified posture report (detection + enforcement + behavioral)")
                .value_name("URL")
                .num_args(1),
        )
        .arg(
            Arg::new("posture-summary")
                .long("posture-summary")
                .help("Generate posture summary JSON (detection + behavioral paired-control)")
                .value_name("URL")
                .num_args(1),
        )
        .arg(
            Arg::new("posture-va2")
                .long("posture-va2")
                .help("Include behavioral analysis in posture report (requires consent)")
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
                .help("Run enforcement test — send attack payloads and measure block rates (requires consent)")
                .value_name("URL")
                .num_args(1),
        )
        .arg(
            Arg::new("perf-report")
                .long("perf-report")
                .help("Write current performance snapshot (p95/p99) to JSON file")
                .value_name("FILE")
                .global(true),
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
                .help("Print planned enforcement payloads without executing")
                .action(clap::ArgAction::SetTrue)
                .requires("va"),
        )
        .arg(
            Arg::new("va-top")
                .long("va-top")
                .help("Number of enforcement results to print")
                .value_name("COUNT")
                .value_parser(clap::value_parser!(u8))
                .default_value("3")
                .requires("va"),
        )
        .arg(
            Arg::new("va-reason-level")
                .long("va-reason-level")
                .help("Reason verbosity (0=none, 1=default)")
                .value_name("LEVEL")
                .value_parser(clap::value_parser!(u8))
                .default_value("1")
                .requires("va"),
        )
        .arg(
            Arg::new("va-max-len")
                .long("va-max-len")
                .help("Max payload length to print in enforcement output")
                .value_name("LEN")
                .value_parser(clap::value_parser!(u16))
                .default_value("80")
                .requires("va"),
        )
        .arg(
            Arg::new("va-output")
                .long("va-output")
                .help("Write enforcement report JSON and summary to file")
                .value_name("FILE")
                .requires("va"),
        )
        .arg(
            Arg::new("va-json")
                .long("va-json")
                .help("Print enforcement report JSON to stdout")
                .action(clap::ArgAction::SetTrue)
                .requires("va"),
        )
        .arg(
            Arg::new("va-replay")
                .long("va-replay")
                .help("Print enforcement replay plan JSON to stdout")
                .action(clap::ArgAction::SetTrue)
                .requires("va"),
        )
        .arg(
            Arg::new("va-replay-csv")
                .long("va-replay-csv")
                .help("Print enforcement replay plan CSV to stdout")
                .action(clap::ArgAction::SetTrue)
                .requires("va"),
        )
        .arg(
            Arg::new("va-tier")
                .long("va-tier")
                .help("Safety tier (1-3)")
                .value_name("TIER")
                .value_parser(clap::value_parser!(u8))
                .default_value("1")
                .requires("va"),
        )
        .arg(
            Arg::new("va-budget")
                .long("va-budget")
                .help("Request budget (max total requests)")
                .value_name("BUDGET")
                .value_parser(clap::value_parser!(u32))
                .default_value("120")
                .requires("va"),
        )
        .arg(
            Arg::new("va-timeout")
                .long("va-timeout")
                .help("Per-request timeout (seconds)")
                .value_name("SECONDS")
                .value_parser(clap::value_parser!(u64))
                .default_value("15")
                .requires("va"),
        )
        .arg(
            Arg::new("va-delay")
                .long("va-delay")
                .help("Delay between requests (milliseconds)")
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
        .group(
            ArgGroup::new("scan-output-format")
                .args(["json", "yaml", "compact", "ndjson"])
                .multiple(false),
        )
        .group(
            ArgGroup::new("exclusive-mode")
                .args([
                    "list",
                    "consent",
                    "benchmark",
                    "effectiveness",
                    "smoke-test",
                    "va-schema",
                    "posture",
                    "posture-summary",
                    "va2",
                    "va",
                    "va-replay-run",
                ])
                .multiple(false),
        )
}

// Backward compatibility aliases
pub use build_simple_cli as build_cli;
pub use SimpleCliApp as CliApp;
