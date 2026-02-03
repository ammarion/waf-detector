use waf_detector::cli::build_simple_cli;

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
    let report = waf_detector::virtual_adversary::VaRunReport::new(
        "https://example.com",
        3,
        config.clone(),
    );
    assert_eq!(report.config.tier, config.tier);
    assert_eq!(report.config.request_budget, config.request_budget);
}

#[test]
fn test_va_cli_output_requires_va() {
    let cmd = build_simple_cli();
    let result = cmd.try_get_matches_from([
        "waf-detect",
        "--va-output",
        "report.json",
    ]);
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
    report.results.push(waf_detector::virtual_adversary::VaResultRecord {
        payload: "payload".to_string(),
        category: waf_detector::virtual_adversary::VaPayloadCategory::SqlInjection,
        outcome: waf_detector::virtual_adversary::VaOutcome::Blocked,
        reason: "status=403".to_string(),
        evidence: Vec::new(),
    });
    assert_eq!(report.results[0].reason, "status=403");
}
