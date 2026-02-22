use waf_detector::cli::{build_simple_cli, SimpleCliApp};

#[test]
fn test_va_cli_defaults() {
    let cmd = build_simple_cli();
    let matches = cmd
        .try_get_matches_from(["waf-detect", "--va", "https://example.com"])
        .expect("CLI should parse VA defaults");

    assert_eq!(*matches.get_one::<u8>("va-tier").unwrap(), 1);
    assert_eq!(*matches.get_one::<u32>("va-budget").unwrap(), 120);
    assert_eq!(*matches.get_one::<u64>("va-timeout").unwrap(), 15);
    assert_eq!(*matches.get_one::<u64>("va-delay").unwrap(), 750);
    assert_eq!(*matches.get_one::<u8>("va-variants").unwrap(), 4);
}

#[test]
fn test_cli_builds() {
    build_simple_cli().debug_assert();
}

#[test]
fn test_va_report_config_fields() {
    let config = waf_detector::virtual_adversary::VirtualAdversaryConfig::default();
    let report =
        waf_detector::virtual_adversary::VaRunReport::new("https://example.com", 3, config.clone());
    assert_eq!(report.config.tier, config.tier);
    assert_eq!(report.config.request_budget, config.request_budget);
}

#[test]
fn test_va_cli_output_requires_va() {
    let cmd = build_simple_cli();
    let result = cmd.try_get_matches_from(["waf-detect", "--va-output", "report.json"]);
    assert!(result.is_err());
}

#[test]
fn test_va_schema_flag_parses() {
    let cmd = build_simple_cli();
    let result = cmd.try_get_matches_from(["waf-detect", "--va-schema"]);
    assert!(result.is_ok());
}

#[test]
fn test_va_dry_run_requires_va() {
    let cmd = build_simple_cli();
    let result = cmd.try_get_matches_from(["waf-detect", "--va-dry-run"]);
    assert!(result.is_err());
}

#[test]
fn test_va_top_default_value() {
    let cmd = build_simple_cli();
    let matches = cmd
        .try_get_matches_from(["waf-detect", "--va", "https://example.com"])
        .expect("VA CLI should parse");
    assert_eq!(*matches.get_one::<u8>("va-top").unwrap(), 3);
}

#[test]
fn test_va_reason_level_default() {
    let cmd = build_simple_cli();
    let matches = cmd
        .try_get_matches_from(["waf-detect", "--va", "https://example.com"])
        .expect("VA CLI should parse");
    assert_eq!(*matches.get_one::<u8>("va-reason-level").unwrap(), 1);
}

#[test]
fn test_va_max_len_default() {
    let cmd = build_simple_cli();
    let matches = cmd
        .try_get_matches_from(["waf-detect", "--va", "https://example.com"])
        .expect("VA CLI should parse");
    assert_eq!(*matches.get_one::<u16>("va-max-len").unwrap(), 80);
}

#[test]
fn test_va_json_requires_va() {
    let cmd = build_simple_cli();
    let result = cmd.try_get_matches_from(["waf-detect", "--va-json"]);
    assert!(result.is_err());
}

#[test]
fn test_va_output_requires_va() {
    let cmd = build_simple_cli();
    let result = cmd.try_get_matches_from(["waf-detect", "--va-output", "out.json"]);
    assert!(result.is_err());
}

#[test]
fn test_va_replay_requires_va() {
    let cmd = build_simple_cli();
    let result = cmd.try_get_matches_from(["waf-detect", "--va-replay"]);
    assert!(result.is_err());
}

#[test]
fn test_va_replay_csv_requires_va() {
    let cmd = build_simple_cli();
    let result = cmd.try_get_matches_from(["waf-detect", "--va-replay-csv"]);
    assert!(result.is_err());
}

#[test]
fn test_va_replay_run_parses() {
    let cmd = build_simple_cli();
    let result = cmd.try_get_matches_from(["waf-detect", "--va-replay-run", "report.json"]);
    assert!(result.is_ok());
}

#[test]
fn test_va2_cli_defaults() {
    let cmd = build_simple_cli();
    let matches = cmd
        .try_get_matches_from(["waf-detect", "--va2", "https://example.com"])
        .expect("CLI should parse VA2 defaults");

    assert_eq!(*matches.get_one::<u64>("va2-seed").unwrap(), 1337);
    assert_eq!(*matches.get_one::<u32>("va2-budget").unwrap(), 60);
    assert_eq!(
        matches.get_one::<String>("va2-phases").unwrap(),
        "baseline,protocol-variance"
    );
}

#[test]
fn test_va2_dry_run_requires_va2() {
    let cmd = build_simple_cli();
    let result = cmd.try_get_matches_from(["waf-detect", "--va2-dry-run"]);
    assert!(result.is_err());
}

#[test]
fn test_va2_run_requires_va2() {
    let cmd = build_simple_cli();
    let result = cmd.try_get_matches_from(["waf-detect", "--va2-run"]);
    assert!(result.is_err());
}

#[test]
fn test_va2_json_requires_va2() {
    let cmd = build_simple_cli();
    let result = cmd.try_get_matches_from(["waf-detect", "--va2-json"]);
    assert!(result.is_err());
}

#[test]
fn test_va_confidence_score_format() {
    let summary = waf_detector::virtual_adversary::VaResultSummary {
        total: 4,
        blocked: 2,
        challenge: 1,
        allowed: 1,
        error: 0,
    };
    assert!((summary.confidence_score() - 0.75).abs() < 0.001);
}

#[test]
fn test_va_report_top_results_has_reason() {
    let mut report = waf_detector::virtual_adversary::VaRunReport::new(
        "https://example.com",
        1,
        waf_detector::virtual_adversary::VirtualAdversaryConfig::default(),
    );
    report
        .results
        .push(waf_detector::virtual_adversary::VaResultRecord {
            payload: "payload".to_string(),
            category: waf_detector::virtual_adversary::VaPayloadCategory::SqlInjection,
            outcome: waf_detector::virtual_adversary::VaOutcome::Blocked,
            reason: "status=403".to_string(),
            evidence: Vec::new(),
        });
    assert_eq!(report.results[0].reason, "status=403");
}

#[test]
fn test_ndjson_flag_parses() {
    let cmd = build_simple_cli();
    let matches = cmd
        .try_get_matches_from(["waf-detect", "https://example.com", "--ndjson"])
        .expect("ndjson flag should parse");
    assert!(matches.get_flag("ndjson"));
}

#[test]
fn test_stdin_flag_parses() {
    let cmd = build_simple_cli();
    let matches = cmd
        .try_get_matches_from(["waf-detect", "--stdin", "--compact"])
        .expect("stdin flag should parse");
    assert!(matches.get_flag("stdin"));
}

#[test]
fn test_fail_on_error_flag_parses() {
    let cmd = build_simple_cli();
    let matches = cmd
        .try_get_matches_from(["waf-detect", "example.com", "--fail-on-error"])
        .expect("fail-on-error flag should parse");
    assert!(matches.get_flag("fail-on-error"));
}

#[test]
fn test_output_format_flags_are_mutually_exclusive() {
    let cmd = build_simple_cli();
    let result = cmd.try_get_matches_from(["waf-detect", "example.com", "--json", "--yaml"]);
    assert!(result.is_err());
}

#[test]
fn test_primary_modes_are_mutually_exclusive() {
    let cmd = build_simple_cli();
    let result = cmd.try_get_matches_from(["waf-detect", "--list", "--benchmark", "fixtures.json"]);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_smoke_test_rejects_multiple_targets_runtime_validation() {
    let app = SimpleCliApp::new().await.expect("app should initialize");
    let matches = build_simple_cli()
        .try_get_matches_from(["waf-detect", "--smoke-test", "a.com", "b.com"])
        .expect("arguments should parse");

    let err = app
        .run_with_matches(matches)
        .await
        .expect_err("runtime validation should reject multiple smoke test targets");
    assert!(err.to_string().contains("exactly one TARGET"));
}

#[tokio::test]
async fn test_scan_only_flags_rejected_in_special_modes() {
    let app = SimpleCliApp::new().await.expect("app should initialize");
    let matches = build_simple_cli()
        .try_get_matches_from(["waf-detect", "--list", "--json"])
        .expect("arguments should parse");

    let err = app
        .run_with_matches(matches)
        .await
        .expect_err("runtime validation should reject scan-only flags in special mode");
    assert!(err.to_string().contains("Scan-only flags"));
}

#[tokio::test]
async fn test_va2_accepts_domain_without_scheme() {
    let app = SimpleCliApp::new().await.expect("app should initialize");
    let matches = build_simple_cli()
        .try_get_matches_from(["waf-detect", "--va2", "example.com"])
        .expect("arguments should parse");

    app.run_with_matches(matches)
        .await
        .expect("va2 dry run should accept bare domains");
}

#[tokio::test]
async fn test_va_dry_run_accepts_domain_without_scheme() {
    let app = SimpleCliApp::new().await.expect("app should initialize");
    let matches = build_simple_cli()
        .try_get_matches_from(["waf-detect", "--va", "example.com", "--va-dry-run"])
        .expect("arguments should parse");

    app.run_with_matches(matches)
        .await
        .expect("va dry run should accept bare domains");
}

#[test]
fn test_scan_subcommand_parses() {
    let matches = build_simple_cli()
        .try_get_matches_from(["waf-detect", "scan", "example.com", "--ndjson"])
        .expect("scan subcommand should parse");
    let sub = matches
        .subcommand_matches("scan")
        .expect("scan subcommand should exist");
    assert!(sub.get_flag("ndjson"));
}

#[test]
fn test_va_subcommand_defaults() {
    let matches = build_simple_cli()
        .try_get_matches_from(["waf-detect", "va", "https://example.com"])
        .expect("va subcommand should parse");
    let sub = matches
        .subcommand_matches("va")
        .expect("va subcommand should exist");

    assert_eq!(*sub.get_one::<u8>("tier").unwrap(), 1);
    assert_eq!(*sub.get_one::<u32>("budget").unwrap(), 120);
    assert_eq!(*sub.get_one::<u64>("timeout").unwrap(), 15);
    assert_eq!(*sub.get_one::<u64>("delay").unwrap(), 750);
    assert_eq!(*sub.get_one::<u8>("variants").unwrap(), 4);
}

#[test]
fn test_va2_subcommand_defaults() {
    let matches = build_simple_cli()
        .try_get_matches_from(["waf-detect", "va2", "https://example.com"])
        .expect("va2 subcommand should parse");
    let sub = matches
        .subcommand_matches("va2")
        .expect("va2 subcommand should exist");

    assert_eq!(*sub.get_one::<u64>("seed").unwrap(), 1337);
    assert_eq!(*sub.get_one::<u32>("budget").unwrap(), 60);
    assert_eq!(
        sub.get_one::<String>("phases").unwrap(),
        "baseline,protocol-variance"
    );
}

#[test]
fn test_benchmark_subcommand_parses() {
    let matches = build_simple_cli()
        .try_get_matches_from(["waf-detect", "benchmark", "benchmark_corpus.json"])
        .expect("benchmark subcommand should parse");
    assert!(matches.subcommand_matches("benchmark").is_some());
}

#[test]
fn test_web_subcommand_is_removed() {
    let has_web_subcommand = build_simple_cli()
        .get_subcommands()
        .any(|subcommand| subcommand.get_name() == "web");
    assert!(!has_web_subcommand);

    let matches = build_simple_cli()
        .try_get_matches_from(["waf-detect", "web"])
        .expect("legacy positional mode should still parse targets");
    assert!(matches.subcommand_name().is_none());
    let targets: Vec<&str> = matches
        .get_many::<String>("targets")
        .expect("target should be present")
        .map(String::as_str)
        .collect();
    assert_eq!(targets, vec!["web"]);
}

#[test]
fn test_providers_subcommand_parses() {
    let matches = build_simple_cli()
        .try_get_matches_from(["waf-detect", "providers"])
        .expect("providers subcommand should parse");
    assert!(matches.subcommand_matches("providers").is_some());
}

#[test]
fn test_doctor_subcommand_parses() {
    let matches = build_simple_cli()
        .try_get_matches_from(["waf-detect", "doctor", "--json", "--strict"])
        .expect("doctor subcommand should parse");
    let sub = matches
        .subcommand_matches("doctor")
        .expect("doctor subcommand should exist");
    assert!(sub.get_flag("json"));
    assert!(sub.get_flag("strict"));
}

#[test]
fn test_completions_subcommand_parses() {
    let matches = build_simple_cli()
        .try_get_matches_from([
            "waf-detect",
            "completions",
            "zsh",
            "--output",
            "/tmp/wd.zsh",
        ])
        .expect("completions subcommand should parse");
    let sub = matches
        .subcommand_matches("completions")
        .expect("completions subcommand should exist");
    assert_eq!(sub.get_one::<String>("shell").unwrap(), "zsh");
    assert_eq!(sub.get_one::<String>("output").unwrap(), "/tmp/wd.zsh");
}

#[tokio::test]
async fn test_va_subcommand_dry_run_accepts_domain() {
    let app = SimpleCliApp::new().await.expect("app should initialize");
    let matches = build_simple_cli()
        .try_get_matches_from(["waf-detect", "va", "example.com", "--dry-run"])
        .expect("va subcommand should parse");

    app.run_with_matches(matches)
        .await
        .expect("va subcommand dry run should accept bare domains");
}

#[tokio::test]
async fn test_va2_subcommand_dry_run_accepts_domain() {
    let app = SimpleCliApp::new().await.expect("app should initialize");
    let matches = build_simple_cli()
        .try_get_matches_from(["waf-detect", "va2", "example.com"])
        .expect("va2 subcommand should parse");

    app.run_with_matches(matches)
        .await
        .expect("va2 subcommand dry run should accept bare domains");
}

#[tokio::test]
async fn test_subcommand_rejects_legacy_root_flags() {
    let app = SimpleCliApp::new().await.expect("app should initialize");
    let matches = build_simple_cli()
        .try_get_matches_from(["waf-detect", "--json", "scan", "example.com"])
        .expect("mixed mode arguments should parse");

    let err = app
        .run_with_matches(matches)
        .await
        .expect_err("runtime should reject mixed legacy root flags with subcommands");
    assert!(err.to_string().contains("Do not mix legacy root flags"));
}
