//! Simple CLI Interface - Modern and intuitive WAF detection

use crate::active::{
    guard_target, resolve_authorized_target, ActiveTargetProfile, ACTIVE_TARGET_PROFILE_ENV,
    OPERATOR_ID_ENV,
};
use crate::audit::AuditSession;
use crate::engine::DetectionEngine;
use crate::hardening::{
    CiGateMode, HardeningConfig, HardeningOrchestrator, RegressionRunner, VendorMode,
};
use crate::origin_probe::{OriginProbeConfig, OriginProber};
use crate::payload::waf_smoke_test::{SmokeTestConfig, WafSmokeTest};
use crate::posture::PostureBuilder;
use crate::providers::{
    akamai::AkamaiProvider, aws::AwsProvider, azure::AzureProvider, cloudflare::CloudFlareProvider,
    f5::F5Provider, fastly::FastlyProvider, fortiweb::FortiWebProvider, imperva::ImpervaProvider,
    modsecurity::ModSecurityProvider, radware::RadwareProvider, sucuri::SucuriProvider,
    vercel::VercelProvider, Provider,
};
use crate::registry::ProviderRegistry;
use crate::surface::{CompilerInputs, SurfaceMap, SurfaceMapCompiler, AUTH_PROFILE_ENV};
use crate::virtual_adversary::{VirtualAdversaryConfig, VirtualAdversaryRunner};
use crate::virtual_adversary2::{build_va2_campaign_plan, Va2CampaignConfig, Va2Phase, Va2Runner};
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
mod output;
pub use benchmark::BenchmarkReport;
use benchmark::{BenchmarkMode, BenchmarkOptions};
use output::{emit_scan_results, print_batch_summary, truncate_with_ellipsis};

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

struct RuntimeEnvGuard {
    active_target_profile: Option<String>,
    operator_id: Option<String>,
    auth_profile: Option<String>,
}

impl RuntimeEnvGuard {
    fn apply(matches: &ArgMatches) -> Result<Self> {
        let guard = Self {
            active_target_profile: std::env::var(ACTIVE_TARGET_PROFILE_ENV).ok(),
            operator_id: std::env::var(OPERATOR_ID_ENV).ok(),
            auth_profile: std::env::var(AUTH_PROFILE_ENV).ok(),
        };

        if let Some(profile) = matches.get_one::<String>("active-target-profile") {
            ActiveTargetProfile::parse(profile)?;
            std::env::set_var(ACTIVE_TARGET_PROFILE_ENV, profile);
        }
        if let Some(operator_id) = matches.get_one::<String>("operator-id") {
            std::env::set_var(OPERATOR_ID_ENV, operator_id);
        }
        if let Some(auth_profile) = matches.get_one::<String>("auth-profile") {
            std::env::set_var(AUTH_PROFILE_ENV, auth_profile);
        }

        Ok(guard)
    }
}

impl Drop for RuntimeEnvGuard {
    fn drop(&mut self) {
        if let Some(value) = &self.active_target_profile {
            std::env::set_var(ACTIVE_TARGET_PROFILE_ENV, value);
        } else {
            std::env::remove_var(ACTIVE_TARGET_PROFILE_ENV);
        }
        if let Some(value) = &self.operator_id {
            std::env::set_var(OPERATOR_ID_ENV, value);
        } else {
            std::env::remove_var(OPERATOR_ID_ENV);
        }
        if let Some(value) = &self.auth_profile {
            std::env::set_var(AUTH_PROFILE_ENV, value);
        } else {
            std::env::remove_var(AUTH_PROFILE_ENV);
        }
    }
}

fn completion_subcommands() -> &'static [&'static str] {
    &[
        "scan",
        "hardening",
        "regression",
        "surface-map",
        "va",
        "va2",
        "benchmark",
        "providers",
        "doctor",
        "completions",
        "origin-probe",
    ]
}

fn completion_global_options() -> &'static [&'static str] {
    &[
        "-h",
        "--help",
        "-V",
        "--version",
        "--perf-report",
        "--active-target-profile",
        "--operator-id",
        "--auth-profile",
        "--allow-legacy-replay",
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
        "--effectiveness",
        "--effectiveness-config",
        "--effectiveness-output",
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
        "--active-target-profile",
        "--operator-id",
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

fn completion_hardening_options() -> &'static [&'static str] {
    &[
        "--active-target-profile",
        "--operator-id",
        "--auth-profile",
        "--json",
        "--output",
        "--regression-pack",
        "--surface-map",
        "--repo",
        "--spec",
        "--har",
        "--manifest",
        "--surface-map-output",
        "--ci-gate",
        "--vendor",
        "--perf-report",
        "-h",
        "--help",
    ]
}

fn completion_regression_options() -> &'static [&'static str] {
    &[
        "--active-target-profile",
        "--operator-id",
        "--auth-profile",
        "--target",
        "--json",
        "--output",
        "--perf-report",
        "-h",
        "--help",
    ]
}

fn completion_surface_map_options() -> &'static [&'static str] {
    &[
        "--active-target-profile",
        "--operator-id",
        "--auth-profile",
        "--repo",
        "--spec",
        "--har",
        "--manifest",
        "--output",
        "--perf-report",
        "-h",
        "--help",
    ]
}

fn completion_va_options() -> &'static [&'static str] {
    &[
        "--active-target-profile",
        "--operator-id",
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
        "--active-target-profile",
        "--operator-id",
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

fn completion_origin_probe_options() -> &'static [&'static str] {
    &[
        "--json",
        "--no-attack-probe",
        "--timeout",
        "--delay",
        "--max-paths",
        "--perf-report",
        "-h",
        "--help",
    ]
}

fn render_bash_completion() -> String {
    let subs = completion_subcommands().join(" ");
    let globals = completion_global_options().join(" ");
    let scan_opts = completion_scan_options().join(" ");
    let hardening_opts = completion_hardening_options().join(" ");
    let regression_opts = completion_regression_options().join(" ");
    let surface_map_opts = completion_surface_map_options().join(" ");
    let va_opts = completion_va_options().join(" ");
    let va2_opts = completion_va2_options().join(" ");
    let benchmark_opts = completion_benchmark_options().join(" ");
    let doctor_opts = completion_doctor_options().join(" ");
    let completions_opts = completion_completions_options().join(" ");
    let origin_probe_opts = completion_origin_probe_options().join(" ");

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
      hardening) opts="{hardening_opts}" ;;
      regression) opts="{regression_opts}" ;;
      surface-map) opts="{surface_map_opts}" ;;
      va) opts="{va_opts}" ;;
      va2) opts="{va2_opts}" ;;
      benchmark) opts="{benchmark_opts}" ;;
      providers) opts="--perf-report -h --help" ;;
      doctor) opts="{doctor_opts}" ;;
    completions) opts="{completions_opts}" ;;
    origin-probe) opts="{origin_probe_opts}" ;;
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
    let hardening_opts = completion_hardening_options().join(" ");
    let regression_opts = completion_regression_options().join(" ");
    let surface_map_opts = completion_surface_map_options().join(" ");
    let va_opts = completion_va_options().join(" ");
    let va2_opts = completion_va2_options().join(" ");
    let benchmark_opts = completion_benchmark_options().join(" ");
    let doctor_opts = completion_doctor_options().join(" ");
    let completions_opts = completion_completions_options().join(" ");
    let origin_probe_opts = completion_origin_probe_options().join(" ");
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
      hardening) opts=({hardening_opts}) ;;
      regression) opts=({regression_opts}) ;;
      surface-map) opts=({surface_map_opts}) ;;
      va) opts=({va_opts}) ;;
      va2) opts=({va2_opts}) ;;
      benchmark) opts=({benchmark_opts}) ;;
      providers) opts=(--perf-report -h --help) ;;
      doctor) opts=({doctor_opts}) ;;
    completions) opts=({completions_opts}) ;;
    origin-probe) opts=({origin_probe_opts}) ;;
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
        ("hardening", completion_hardening_options()),
        ("regression", completion_regression_options()),
        ("surface-map", completion_surface_map_options()),
        ("va", completion_va_options()),
        ("va2", completion_va2_options()),
        ("benchmark", completion_benchmark_options()),
        ("providers", &["--perf-report", "-h", "--help"][..]),
        ("doctor", completion_doctor_options()),
        ("completions", completion_completions_options()),
        ("origin-probe", completion_origin_probe_options()),
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
        let _runtime_env = RuntimeEnvGuard::apply(&matches)?;

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
            let target = resolve_authorized_target(&normalized)?;
            let mut plan = build_va2_campaign_plan(
                &target.normalized_url,
                &phases,
                Va2CampaignConfig {
                    seed: 1337,
                    budget: 12,
                },
            )?;
            for step in &mut plan.steps {
                step.delay_ms = 0;
            }
            let mut audit = AuditSession::new("posture_summary_va2", &target, true)?;
            let runner = Va2Runner::new()?;
            let mut va2_report = match runner.run_plan_with_target(plan, &target).await {
                Ok(report) => report,
                Err(err) => {
                    audit.record_failed(&err.to_string())?;
                    return Err(err);
                }
            };
            audit.record_completed()?;
            va2_report.audit = Some(audit.snapshot());
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
                let target = resolve_authorized_target(&normalized)?;
                let mut plan = build_va2_campaign_plan(&target.normalized_url, &phases, config)?;
                for step in &mut plan.steps {
                    step.delay_ms = 0;
                }
                let mut audit = AuditSession::new("posture_va2", &target, true)?;
                let runner = Va2Runner::new()?;
                let mut report = match runner.run_plan_with_target(plan, &target).await {
                    Ok(report) => report,
                    Err(err) => {
                        audit.record_failed(&err.to_string())?;
                        return Err(err);
                    }
                };
                audit.record_completed()?;
                report.audit = Some(audit.snapshot());
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

            if matches.get_flag("va2-run") {
                let target = resolve_authorized_target(&normalized)?;
                let plan = build_va2_campaign_plan(&target.normalized_url, &phases, config)?;
                let mut audit = AuditSession::new("va2", &target, true)?;
                let runner = Va2Runner::new()?;
                let mut report = match runner.run_plan_with_target(plan, &target).await {
                    Ok(report) => report,
                    Err(err) => {
                        audit.record_failed(&err.to_string())?;
                        return Err(err);
                    }
                };
                audit.record_completed()?;
                report.audit = Some(audit.snapshot());
                let mut audit = Some(audit);
                self.emit_va2_report(&mut report, &matches, "va2-json", "va2-output", &mut audit)?;
                self.write_perf_report_if_requested(&matches)?;
                return Ok(());
            }

            let plan = build_va2_campaign_plan(&normalized, &phases, config)?;
            self.emit_va2_plan(&plan, &matches, "va2-json", "va2-output")?;
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
            self.validate_va_replay_report(&report, matches.get_flag("allow-legacy-replay"))?;
            let target = matches
                .get_one::<String>("va-replay-target")
                .cloned()
                .unwrap_or_else(|| report.target_url.clone());
            let target = resolve_authorized_target(&target)?;
            let mut audit = AuditSession::new("va_replay", &target, true)?;
            let mut runner = VirtualAdversaryRunner::new(report.config.clone())?;
            let mut report =
                match runner.run_replay_plan_with_target(&target, report.replay_plan.clone()) {
                    Ok(report) => report,
                    Err(err) => {
                        audit.record_failed(&err.to_string())?;
                        return Err(err);
                    }
                };
            audit.record_completed()?;
            report.audit = Some(audit.snapshot());
            let mut audit = Some(audit);
            self.emit_va_report(
                &mut report,
                &matches,
                "va-json",
                "va-replay",
                "va-replay-csv",
                "va-output",
                "va-top",
                "va-reason-level",
                "va-max-len",
                true,
                &mut audit,
            )?;
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
            let target = resolve_authorized_target(&normalized)?;
            let mut audit = AuditSession::new("va", &target, true)?;
            let mut report = match runner.run_with_events_for_target(&target, |_, _| {}, |_| {}) {
                Ok(report) => report,
                Err(err) => {
                    audit.record_failed(&err.to_string())?;
                    return Err(err);
                }
            };
            audit.record_completed()?;
            report.audit = Some(audit.snapshot());
            let mut audit = Some(audit);
            self.emit_va_report(
                &mut report,
                &matches,
                "va-json",
                "va-replay",
                "va-replay-csv",
                "va-output",
                "va-top",
                "va-reason-level",
                "va-max-len",
                false,
                &mut audit,
            )?;
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
            "hardening" => {
                let result = self.run_hardening_subcommand(matches).await;
                self.write_perf_report_if_requested(matches)?;
                result
            }
            "regression" => {
                let result = self.run_regression_subcommand(matches).await;
                self.write_perf_report_if_requested(matches)?;
                result
            }
            "surface-map" => {
                let result = self.run_surface_map_subcommand(matches).await;
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
            "report" => {
                self.run_report_subcommand(matches)?;
                self.write_perf_report_if_requested(matches)?;
                Ok(())
            }
            "origin-probe" => {
                let result = self.run_origin_probe_subcommand(matches).await;
                self.write_perf_report_if_requested(matches)?;
                result
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

        if matches.get_flag("payload-analysis") {
            self.ensure_owned_targets_registered(&targets, "active payload analysis")?;
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

    async fn run_hardening_subcommand(&self, matches: &ArgMatches) -> Result<()> {
        let target = matches
            .get_one::<String>("target")
            .ok_or_else(|| anyhow!("hardening requires a target URL"))?;
        let normalized = self.normalize_url(target)?;
        let ci_gate = CiGateMode::parse(
            matches
                .get_one::<String>("ci-gate")
                .map(String::as_str)
                .unwrap_or("off"),
        )?;
        let vendor_mode = VendorMode::parse(
            matches
                .get_one::<String>("vendor")
                .map(String::as_str)
                .unwrap_or("auto"),
        )?;

        let surface_map = self.load_or_compile_surface_map(matches, &normalized)?;
        let config = HardeningConfig {
            ci_gate,
            vendor_mode,
            surface_map,
            ..HardeningConfig::default()
        };
        let orchestrator = HardeningOrchestrator::new(self.registry.clone(), config);
        let mut execution = orchestrator.run(&normalized).await?;

        if let Some(path) = matches.get_one::<String>("regression-pack") {
            if let Some(audit) = execution.audit.as_mut() {
                audit.record_artifact_written(path)?;
                execution.report.audit = Some(audit.snapshot());
            }
            let json = serde_json::to_string_pretty(&execution.report.regression_pack)?;
            fs::write(path, json)?;
        }

        if let Some(path) = matches.get_one::<String>("surface-map-output") {
            let Some(surface_map) = execution.refined_surface_map.as_ref() else {
                return Err(anyhow!(
                    "--surface-map-output requires --surface-map or one of --repo/--spec/--har"
                ));
            };
            if let Some(audit) = execution.audit.as_mut() {
                audit.record_artifact_written(path)?;
                execution.report.audit = Some(audit.snapshot());
            }
            fs::write(path, serde_json::to_string_pretty(surface_map)?)?;
        }

        if let Some(path) = matches.get_one::<String>("output") {
            if let Some(audit) = execution.audit.as_mut() {
                audit.record_artifact_written(path)?;
                execution.report.audit = Some(audit.snapshot());
            }
            let json = serde_json::to_string_pretty(&execution.report)?;
            fs::write(path, json)?;
            println!("Hardening report saved to: {path}");
        }

        if matches.get_flag("json") {
            println!("{}", serde_json::to_string_pretty(&execution.report)?);
        } else if matches.get_one::<String>("output").is_none() {
            self.print_hardening_report(&execution.report);
        }

        if execution.report.summary.ci_gate_triggered {
            let ids =
                crate::hardening::finding::ci_gate_failures(&execution.report.findings, ci_gate)
                    .map(|finding| finding.id.clone())
                    .collect::<Vec<_>>();
            return Err(anyhow!(
                "hardening CI gate '{}' triggered by findings: {}",
                ci_gate.as_str(),
                ids.join(", ")
            ));
        }

        Ok(())
    }

    async fn run_surface_map_subcommand(&self, matches: &ArgMatches) -> Result<()> {
        let target = matches
            .get_one::<String>("target")
            .ok_or_else(|| anyhow!("surface-map requires a target URL"))?;
        let normalized = self.normalize_url(target)?;

        let Some(surface_map) = self.load_or_compile_surface_map(matches, &normalized)? else {
            return Err(anyhow!(
                "surface-map requires at least one of --repo, --spec, or --har"
            ));
        };

        if let Some(path) = matches.get_one::<String>("output") {
            fs::write(path, serde_json::to_string_pretty(&surface_map)?)?;
            println!("Surface map saved to: {path}");
        } else {
            println!("Surface Map: {}", surface_map.target_base_url);
            println!("  Endpoints: {}", surface_map.summary.total_endpoints);
            println!(
                "  Auth required: {}",
                surface_map.summary.auth_required_endpoints
            );
            println!(
                "  Sources: {}",
                surface_map
                    .summary
                    .sources
                    .iter()
                    .map(|(source, count)| format!("{source}={count}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            for endpoint in surface_map.endpoints.iter().take(10) {
                println!(
                    "  [{}] {} {} ({:.0}% confidence)",
                    endpoint.priority.as_str(),
                    endpoint.methods.join(","),
                    endpoint.path_template,
                    endpoint.confidence * 100.0
                );
            }
        }

        Ok(())
    }

    async fn run_regression_subcommand(&self, matches: &ArgMatches) -> Result<()> {
        let pack_path = matches
            .get_one::<String>("pack")
            .ok_or_else(|| anyhow!("regression requires a regression pack path"))?;
        let raw = fs::read_to_string(pack_path)?;
        let pack = serde_json::from_str::<crate::hardening::RegressionPack>(&raw)
            .map_err(|err| anyhow!("failed to parse regression pack: {err}"))?;
        let target_override = matches.get_one::<String>("target").map(String::as_str);

        let runner = RegressionRunner::new()?;
        let report = runner.run_pack(&pack, target_override).await?;

        if let Some(path) = matches.get_one::<String>("output") {
            fs::write(path, serde_json::to_string_pretty(&report)?)?;
            println!("Regression report saved to: {path}");
        }

        if matches.get_flag("json") {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else if matches.get_one::<String>("output").is_none() {
            self.print_regression_report(&report);
        }

        if report.failed_assertions > 0 {
            return Err(anyhow!(
                "regression replay failed: {} assertion(s) still open",
                report.failed_assertions
            ));
        }

        Ok(())
    }

    fn load_or_compile_surface_map(
        &self,
        matches: &ArgMatches,
        normalized_target: &str,
    ) -> Result<Option<SurfaceMap>> {
        let surface_map_path = matches
            .try_get_one::<String>("surface-map")
            .ok()
            .flatten()
            .cloned();
        let repo = matches
            .try_get_one::<String>("repo")
            .ok()
            .flatten()
            .cloned();
        let spec = matches
            .try_get_one::<String>("spec")
            .ok()
            .flatten()
            .cloned();
        let har = matches.try_get_one::<String>("har").ok().flatten().cloned();
        let manifest = matches
            .try_get_one::<String>("manifest")
            .ok()
            .flatten()
            .cloned();
        let has_discovery_inputs = repo.is_some() || spec.is_some() || har.is_some();
        let has_compiler_inputs = has_discovery_inputs || manifest.is_some();

        if surface_map_path.is_some() && has_compiler_inputs {
            return Err(anyhow!(
                "--surface-map cannot be combined with --repo, --spec, --har, or --manifest"
            ));
        }

        if let Some(path) = surface_map_path {
            let raw = fs::read_to_string(&path)?;
            return Ok(Some(serde_json::from_str(&raw).map_err(|err| {
                anyhow!("failed to parse surface map {}: {err}", path)
            })?));
        }

        if !has_discovery_inputs {
            return Ok(None);
        }

        let compiler = SurfaceMapCompiler::new();
        let inputs = CompilerInputs {
            target_url: normalized_target.to_string(),
            repo,
            spec: spec.map(PathBuf::from),
            har: har.map(PathBuf::from),
            manifest: manifest.map(PathBuf::from),
        };
        Ok(Some(compiler.compile(inputs)?))
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

        let target = resolve_authorized_target(&normalized)?;
        let mut audit = AuditSession::new("va", &target, true)?;
        let mut report = match runner.run_with_events_for_target(&target, |_, _| {}, |_| {}) {
            Ok(report) => report,
            Err(err) => {
                audit.record_failed(&err.to_string())?;
                return Err(err);
            }
        };
        audit.record_completed()?;
        report.audit = Some(audit.snapshot());
        let mut audit = Some(audit);
        self.emit_va_report(
            &mut report,
            matches,
            "json",
            "replay",
            "replay-csv",
            "output",
            "top",
            "reason-level",
            "max-len",
            false,
            &mut audit,
        )
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

        if matches.get_flag("run") {
            let target = resolve_authorized_target(&normalized)?;
            let plan = build_va2_campaign_plan(&target.normalized_url, &phases, config)?;
            let mut audit = AuditSession::new("va2", &target, true)?;
            let runner = Va2Runner::new()?;
            let mut report = match runner.run_plan_with_target(plan, &target).await {
                Ok(report) => report,
                Err(err) => {
                    audit.record_failed(&err.to_string())?;
                    return Err(err);
                }
            };
            audit.record_completed()?;
            report.audit = Some(audit.snapshot());
            let mut audit = Some(audit);
            return self.emit_va2_report(&mut report, matches, "json", "output", &mut audit);
        }

        let plan = build_va2_campaign_plan(&normalized, &phases, config)?;
        self.emit_va2_plan(&plan, matches, "json", "output")
    }

    fn validate_va_replay_report(
        &self,
        report: &crate::virtual_adversary::VaRunReport,
        allow_legacy_replay: bool,
    ) -> Result<()> {
        match &report.replay_bundle {
            Some(bundle) if bundle.verify_integrity() => Ok(()),
            Some(_) if allow_legacy_replay => Ok(()),
            Some(_) => Err(anyhow!(
                "Replay execution rejected because the replay bundle failed integrity verification. Re-run with `--allow-legacy-replay` to bypass this compatibility check."
            )),
            None if allow_legacy_replay => Ok(()),
            None => Err(anyhow!(
                "Replay execution requires a v2 replay bundle. This report is legacy; re-run with `--allow-legacy-replay` to bypass this compatibility check."
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_va_report(
        &self,
        report: &mut crate::virtual_adversary::VaRunReport,
        matches: &ArgMatches,
        json_flag: &str,
        replay_flag: &str,
        replay_csv_flag: &str,
        output_arg: &str,
        top_arg: &str,
        reason_arg: &str,
        max_len_arg: &str,
        replay_mode: bool,
        audit: &mut Option<AuditSession>,
    ) -> Result<()> {
        if matches.get_flag(json_flag) {
            let json = serde_json::to_string_pretty(report)?;
            println!("{json}");
            return Ok(());
        }

        if matches.get_flag(replay_flag) {
            let json = serde_json::to_string_pretty(&report.replay_plan)?;
            println!("{json}");
            return Ok(());
        }

        if matches.get_flag(replay_csv_flag) {
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

        if let Some(output) = matches.get_one::<String>(output_arg) {
            if let Some(session) = audit.as_mut() {
                session.record_artifact_written(output)?;
                report.audit = Some(session.snapshot());
            }
            let json = serde_json::to_string_pretty(report)?;
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
            if replay_mode {
                println!("📄 Enforcement replay report saved to: {output}");
                println!("📄 Enforcement replay summary saved to: {summary_path}");
            } else {
                println!("📄 Enforcement report saved to: {output}");
                println!("📄 Enforcement summary saved to: {summary_path}");
            }
            return Ok(());
        }

        println!(
            "{}: {} | Total: {} | Blocked: {} | Challenge: {} | Allowed: {} | Error: {} | Confidence: {:.2} | Risk: {} | Enforcement: {:?} | Evidence: {:.2}",
            if replay_mode {
                "🧪 Enforcement Replay"
            } else {
                "🧪 Enforcement Test"
            },
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
        if !replay_mode {
            println!(
                "   Config: tier={} budget={} delay_ms={} timeout_s={} variants={}",
                report.config.tier,
                report.config.request_budget,
                report.config.request_delay.as_millis(),
                report.config.request_timeout.as_secs(),
                report.config.max_variants_per_payload
            );
        }
        let max_results = *matches.get_one::<u8>(top_arg).unwrap_or(&3) as usize;
        if !report.results.is_empty() {
            println!("   Top Results:");
            let reason_level = *matches.get_one::<u8>(reason_arg).unwrap_or(&1);
            let max_len = *matches.get_one::<u16>(max_len_arg).unwrap_or(&80) as usize;
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

    fn emit_va2_plan(
        &self,
        plan: &crate::virtual_adversary2::Va2CampaignPlan,
        matches: &ArgMatches,
        json_flag: &str,
        output_arg: &str,
    ) -> Result<()> {
        if matches.get_flag(json_flag) {
            let json = serde_json::to_string_pretty(plan)?;
            println!("{json}");
            return Ok(());
        }

        if let Some(output) = matches.get_one::<String>(output_arg) {
            let json = serde_json::to_string_pretty(plan)?;
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

    fn emit_va2_report(
        &self,
        report: &mut crate::virtual_adversary2::Va2RunReport,
        matches: &ArgMatches,
        json_flag: &str,
        output_arg: &str,
        audit: &mut Option<AuditSession>,
    ) -> Result<()> {
        if matches.get_flag(json_flag) {
            let json = serde_json::to_string_pretty(report)?;
            println!("{json}");
            return Ok(());
        }

        if let Some(output) = matches.get_one::<String>(output_arg) {
            if let Some(session) = audit.as_mut() {
                session.record_artifact_written(output)?;
                report.audit = Some(session.snapshot());
            }
            let json = serde_json::to_string_pretty(report)?;
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

    fn run_report_subcommand(&self, matches: &ArgMatches) -> Result<()> {
        let input = matches
            .get_one::<String>("input")
            .ok_or_else(|| anyhow!("report requires an input JSON file"))?;
        let output = matches.get_one::<String>("output").map(PathBuf::from);
        let input_path = PathBuf::from(input);
        let rendered = crate::reporting::render_report_file(&input_path, output.as_deref())?;
        println!("HTML report saved to: {}", rendered.display());
        Ok(())
    }

    async fn run_origin_probe_subcommand(&self, matches: &ArgMatches) -> Result<()> {
        let target = matches
            .get_one::<String>("target")
            .ok_or_else(|| anyhow!("origin-probe requires a target URL"))?;
        let normalized = self.normalize_url(target)?;

        let config = OriginProbeConfig {
            timeout: std::time::Duration::from_secs(
                *matches.get_one::<u64>("timeout").unwrap_or(&10),
            ),
            delay_ms: *matches.get_one::<u64>("delay").unwrap_or(&200),
            max_paths_to_check: matches
                .get_one::<usize>("max-paths")
                .copied()
                .unwrap_or(crate::origin_probe::WELL_KNOWN_BYPASS_PATHS.len()),
            send_attack_probe: !matches.get_flag("no-attack-probe"),
        };

        let resolved = resolve_authorized_target(&normalized)?;

        let prober = OriginProber::new(config)?;
        let report = prober.run(&resolved).await?;

        if matches.get_flag("json") {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            println!(
                "Origin probe: {} (origin IP: {})",
                report.target_url, report.origin_ip
            );
            if report.findings.is_empty() {
                println!("  No accessible bypass paths found.");
            } else {
                for finding in &report.findings {
                    let status = if finding.waf_bypassed {
                        "BYPASSED"
                    } else {
                        "accessible"
                    };
                    println!(
                        "  {} {} → HTTP {}",
                        status, finding.bypass_path, finding.status_on_bypass_path
                    );
                    for e in &finding.evidence {
                        println!("    • {e}");
                    }
                }
            }
            if report.bypass_confirmed {
                println!("  [!] WAF bypass confirmed via origin IP");
            } else {
                println!("  WAF bypass not confirmed.");
            }
        }

        Ok(())
    }

    fn validate_matches(&self, matches: &ArgMatches) -> Result<()> {
        let modes = [
            ("--list", matches.get_flag("list")),
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

    fn ensure_owned_targets_registered(&self, targets: &[String], capability: &str) -> Result<()> {
        let scope = crate::effectiveness::consent::ConsentManager::new();
        for target in targets {
            if let Err(err) = guard_target(&scope, target) {
                return Err(anyhow!(
                    "Target {target} is not allowed for {capability}: {err}"
                ));
            }
        }
        Ok(())
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

        emit_scan_results(&[detection_result], format, debug)?;

        if verbose && human_output {
            println!("⏱️  Scan completed in {:.2}ms", scan_time.as_millis());
        }

        Ok(())
    }

    fn print_hardening_report(&self, report: &crate::hardening::HardeningReport) {
        println!("Hardening Report: {}", report.target);
        if let Some(provider) = &report.summary.provider {
            println!(
                "  Provider:   {} ({})",
                provider,
                report.summary.vendor_mode.as_str()
            );
        } else {
            println!(
                "  Provider:   not confidently detected ({})",
                report.summary.vendor_mode.as_str()
            );
        }
        println!(
            "  Surface:    {} ({:.0}% confidence)",
            if report.surface_assessment.suitable {
                "suitable"
            } else {
                "unsuitable"
            },
            report.surface_assessment.confidence * 100.0
        );
        println!(
            "  Findings:   {} total, {} actionable",
            report.summary.total_findings, report.summary.actionable_findings
        );
        if let Some(summary) = &report.surface_map_summary {
            println!(
                "  SurfaceMap: {} endpoints ({} auth required)",
                summary.total_endpoints, summary.auth_required_endpoints
            );
        }
        if let Some(stats) = &report.refined_surface_map_stats {
            println!(
                "  RoutePlan:  {} selected, {} partial, {} auth-uncovered",
                stats.selected_endpoints,
                stats.partial_coverage_endpoints,
                stats.uncovered_auth_required_endpoints
            );
        }
        println!(
            "  CI Gate:    {}{}",
            report.summary.ci_gate.as_str(),
            if report.summary.ci_gate_triggered {
                " (triggered)"
            } else {
                ""
            }
        );
        if !report.summary.notes.is_empty() {
            println!("  Notes:");
            for note in &report.summary.notes {
                println!("    - {note}");
            }
        }
        for finding in report.findings.iter().take(5) {
            println!(
                "  [{}] {} ({:.0}% confidence)",
                finding.severity.as_str(),
                finding.title,
                finding.confidence * 100.0
            );
            println!("    Root cause: {}", finding.likely_root_cause);
            if let Some(guidance) = finding.fix_guidance.first() {
                println!("    Fix:        {guidance}");
            }
        }
    }

    fn print_regression_report(&self, report: &crate::hardening::RegressionRunReport) {
        println!("Regression Replay: {}", report.target);
        println!(
            "  Assertions: {} total, {} passed, {} failed",
            report.total_assertions, report.passed_assertions, report.failed_assertions
        );
        for result in report.results.iter().take(10) {
            println!(
                "  [{}] {} -> {:?} (expected {:?})",
                if result.passed { "pass" } else { "fail" },
                result.finding_id,
                result.observed_action,
                result.expected_action
            );
            for note in &result.notes {
                println!("    - {note}");
            }
        }
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

        emit_scan_results(&results, format, debug)?;

        let error_count = results
            .iter()
            .filter(|result| result.error.is_some())
            .count();
        if human_output {
            print_batch_summary(&results, total_time);
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

        let target = resolve_authorized_target(url)?;
        let mut audit = AuditSession::new("effectiveness", &target, config.audit_logging)?;
        let mut test = EffectivenessTest::new(config).await?;

        // Run the test
        println!("🎯 Target: {}", target.normalized_url);
        println!("⏳ Running comprehensive effectiveness tests...\n");

        let mut report = match test.test_effectiveness_with_target(&target).await {
            Ok(report) => report,
            Err(err) => {
                audit.record_failed(&err.to_string())?;
                return Err(err);
            }
        };
        audit.record_completed()?;
        report.audit = Some(audit.snapshot());

        // Display results
        println!("\n{}", report.generate_summary());

        if let Some(path) = matches.get_one::<String>("effectiveness-output") {
            audit.record_artifact_written(path)?;
            report.audit = Some(audit.snapshot());
            std::fs::write(path, report.to_json()?)?;
            println!("\n📁 Effectiveness report saved to: {path}");
        }

        // Save report if high risk
        if report.risk_score > 50.0 {
            let filename = format!(
                "waf-effectiveness-{}.json",
                chrono::Utc::now().format("%Y%m%d_%H%M%S")
            );
            audit.record_artifact_written(&filename)?;
            report.audit = Some(audit.snapshot());
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
        let target = resolve_authorized_target(&normalized_url)?;
        let mut audit = AuditSession::new("smoke_test", &target, true)?;

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

        let mut result = match smoke_test.run_test_with_target(&target).await {
            Ok(result) => result,
            Err(err) => {
                audit.record_failed(&err.to_string())?;
                return Err(err);
            }
        };
        audit.record_completed()?;
        result.audit = Some(audit.snapshot());

        // Print summary
        smoke_test.print_summary(&result);

        // Export to JSON if requested
        if let Some(output_file) = matches.get_one::<String>("output") {
            audit.record_artifact_written(output_file)?;
            result.audit = Some(audit.snapshot());
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
                .help("Enable active payload-based probing during detection (registered owned targets only)")
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

fn build_hardening_subcommand() -> Command {
    Command::new("hardening")
        .about("Run fix-oriented WAF hardening analysis and emit evidence/regression artifacts")
        .arg(
            Arg::new("target")
                .help("Target URL or domain")
                .value_name("URL")
                .required(true),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .help("Print the full hardening report JSON to stdout")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .help("Write the hardening report JSON to file")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("regression-pack")
                .long("regression-pack")
                .help("Write the generated regression assertion pack to file")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("surface-map")
                .long("surface-map")
                .help("Use an existing surface map JSON artifact instead of compiling one")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("repo")
                .long("repo")
                .help("Frontend repo path or git URL used to compile a route-level surface map")
                .value_name("PATH|URL"),
        )
        .arg(
            Arg::new("spec")
                .long("spec")
                .help("OpenAPI document used to enrich the surface map")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("har")
                .long("har")
                .help("HAR file used to enrich the surface map")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("manifest")
                .long("manifest")
                .help("Optional waf-hardening.yaml override file")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("surface-map-output")
                .long("surface-map-output")
                .help("Write the refined surface map JSON artifact to file")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("ci-gate")
                .long("ci-gate")
                .help("Optional CI gate: off, critical, or any")
                .value_name("MODE")
                .value_parser(["off", "critical", "any"])
                .default_value("off"),
        )
        .arg(
            Arg::new("vendor")
                .long("vendor")
                .help("Vendor-specific hardening guidance mode")
                .value_name("MODE")
                .value_parser(["auto", "cloudflare", "aws"])
                .default_value("auto"),
        )
}

fn build_regression_subcommand() -> Command {
    Command::new("regression")
        .about("Replay a hardening regression pack against an owned target")
        .arg(
            Arg::new("pack")
                .help("Path to a hardening regression pack JSON file")
                .value_name("FILE")
                .required(true),
        )
        .arg(
            Arg::new("target")
                .long("target")
                .help("Optional target override. Replays the pack paths and queries against this URL.")
                .value_name("URL"),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .help("Print the regression replay report JSON to stdout")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .help("Write the regression replay report JSON to file")
                .value_name("FILE"),
        )
}

fn build_surface_map_subcommand() -> Command {
    Command::new("surface-map")
        .about("Compile and refine a route-aware application surface map from repo/spec/HAR inputs")
        .arg(
            Arg::new("target")
                .long("target")
                .help("Owned staging target URL used for live refinement")
                .value_name("URL")
                .required(true),
        )
        .arg(
            Arg::new("repo")
                .long("repo")
                .help("Frontend repo path or git URL")
                .value_name("PATH|URL"),
        )
        .arg(
            Arg::new("spec")
                .long("spec")
                .help("OpenAPI document")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("har")
                .long("har")
                .help("HAR file")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("manifest")
                .long("manifest")
                .help("Optional waf-hardening.yaml override file")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .help("Write the compiled/refined surface map JSON to file")
                .value_name("FILE"),
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
                .help("Execute behavioral analysis")
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

fn build_origin_probe_subcommand() -> Command {
    Command::new("origin-probe")
        .about("Probe for WAF bypass via unprotected endpoints sharing origin IP")
        .arg(
            Arg::new("target")
                .help("Target URL to probe")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .help("Output results as JSON")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no-attack-probe")
                .long("no-attack-probe")
                .help(
                    "Skip attack probe — discovery only (check bypass paths without sending probe)",
                )
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .help("Request timeout in seconds")
                .value_name("SECS")
                .value_parser(clap::value_parser!(u64))
                .default_value("10"),
        )
        .arg(
            Arg::new("delay")
                .long("delay")
                .help("Delay between requests in milliseconds")
                .value_name("MS")
                .value_parser(clap::value_parser!(u64))
                .default_value("200"),
        )
        .arg(
            Arg::new("max-paths")
                .long("max-paths")
                .help("Maximum number of bypass paths to check")
                .value_name("N")
                .value_parser(clap::value_parser!(usize)),
        )
        .arg(
            Arg::new("perf-report")
                .long("perf-report")
                .help("Write performance snapshot to file")
                .value_name("FILE"),
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

fn build_report_subcommand() -> Command {
    Command::new("report")
        .about("Render a saved JSON scan report to standalone HTML")
        .arg(
            Arg::new("input")
                .help("Path to a saved JSON report")
                .value_name("INPUT")
                .required(true),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .short('o')
                .help("Write HTML to a specific file (defaults next to input)")
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
  waf-detect hardening api.example.com --json --regression-pack hardening-pack.json
  waf-detect surface-map --repo ./tokenizer-ui --target https://staging.example.com --output surface-map.json
  waf-detect regression hardening-pack.json --target https://api.example.com
  waf-detect scan @urls.txt --ndjson
  cat urls.txt | waf-detect scan --stdin --compact
  waf-detect va example.com --dry-run
  waf-detect va2 example.com --run --json
  waf-detect benchmark benchmark_corpus.json --workers 8
  waf-detect providers
  waf-detect doctor
  waf-detect report ./scan-report.json -o ./scan-report.html
  waf-detect completions zsh -o ~/.zsh/completions/_waf-detect

LEGACY FLAG MODE (still supported):
  waf-detect cloudflare.com --json
  waf-detect --va https://example.com
  waf-detect --va2 https://example.com --va2-run

The tool automatically adds https:// for bare domains where supported.
        "#,
        )
        .subcommand(build_scan_subcommand())
        .subcommand(build_hardening_subcommand())
        .subcommand(build_regression_subcommand())
        .subcommand(build_surface_map_subcommand())
        .subcommand(build_va_subcommand())
        .subcommand(build_va2_subcommand())
        .subcommand(build_benchmark_subcommand())
        .subcommand(build_providers_subcommand())
        .subcommand(build_doctor_subcommand())
        .subcommand(build_report_subcommand())
        .subcommand(build_completions_subcommand())
        .subcommand(build_origin_probe_subcommand())
        .arg(
            Arg::new("active-target-profile")
                .long("active-target-profile")
                .help("Active testing target profile: public or internal")
                .value_name("PROFILE")
                .value_parser(["public", "internal"])
                .global(true),
        )
        .arg(
            Arg::new("operator-id")
                .long("operator-id")
                .help("Operator identifier recorded in active testing audit trails")
                .value_name("ID")
                .global(true),
        )
        .arg(
            Arg::new("auth-profile")
                .long("auth-profile")
                .help("Path to an auth-profile.yaml file used for non-browser authenticated route testing")
                .value_name("FILE")
                .global(true),
        )
        .arg(
            Arg::new("allow-legacy-replay")
                .long("allow-legacy-replay")
                .help("Allow replay execution from legacy or invalid replay bundles")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        )
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
            Arg::new("effectiveness")
                .long("effectiveness")
                .help("Run comprehensive WAF effectiveness testing")
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
            Arg::new("effectiveness-output")
                .long("effectiveness-output")
                .help("Write the effectiveness report JSON to a file")
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
                .help("Execute behavioral analysis")
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
                .help("Include behavioral analysis in posture report")
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
                .help("Run enforcement test — send attack payloads and measure block rates")
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
