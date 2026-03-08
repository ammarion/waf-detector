use std::net::{IpAddr, Ipv4Addr};
use waf_detector::origin_probe::{
    OriginFinding, OriginProbeConfig, OriginProbeReport, WELL_KNOWN_BYPASS_PATHS,
};

#[test]
fn test_well_known_paths_non_empty() {
    assert!(
        WELL_KNOWN_BYPASS_PATHS.len() >= 10,
        "expected at least 10 well-known bypass paths, got {}",
        WELL_KNOWN_BYPASS_PATHS.len()
    );
}

#[test]
fn test_origin_probe_config_defaults() {
    let config = OriginProbeConfig::default();
    assert_eq!(config.timeout.as_secs(), 10);
    assert_eq!(config.delay_ms, 200);
    assert_eq!(config.max_paths_to_check, WELL_KNOWN_BYPASS_PATHS.len());
    assert!(config.send_attack_probe);
}

#[test]
fn test_no_attack_probe_flag_sets_config_field() {
    let config = OriginProbeConfig {
        send_attack_probe: false,
        ..OriginProbeConfig::default()
    };
    assert!(!config.send_attack_probe);
}

#[test]
fn test_bypass_confirmed_reflects_findings() {
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let findings = vec![
        OriginFinding {
            bypass_path: "/health".to_string(),
            bypass_url: "https://example.com/health".to_string(),
            origin_ip: ip,
            status_on_bypass_path: 200,
            status_on_main_via_origin: 200,
            waf_bypassed: false,
            evidence: vec![],
        },
        OriginFinding {
            bypass_path: "/status".to_string(),
            bypass_url: "https://example.com/status".to_string(),
            origin_ip: ip,
            status_on_bypass_path: 200,
            status_on_main_via_origin: 200,
            waf_bypassed: true,
            evidence: vec!["bypassed".to_string()],
        },
    ];

    let report = OriginProbeReport {
        target_url: "https://example.com".to_string(),
        target_host: "example.com".to_string(),
        origin_ip: ip,
        bypass_confirmed: findings.iter().any(|f| f.waf_bypassed),
        findings,
    };

    assert!(report.bypass_confirmed);
}

#[test]
fn test_origin_probe_cli_parses() {
    let app = waf_detector::cli::build_simple_cli();
    let result = app.try_get_matches_from(vec!["waf-detect", "origin-probe", "--help"]);
    // --help causes an early exit with a DisplayHelp error, which is expected
    if let Err(e) = result {
        assert_eq!(e.kind(), clap::error::ErrorKind::DisplayHelp);
    }
}
