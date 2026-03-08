use waf_detector::cli::build_simple_cli;

#[test]
fn test_hardening_subcommand_defaults() {
    let matches = build_simple_cli()
        .try_get_matches_from(["waf-detect", "hardening", "https://example.com"])
        .expect("hardening subcommand should parse");
    let sub = matches
        .subcommand_matches("hardening")
        .expect("hardening subcommand should exist");

    assert_eq!(sub.get_one::<String>("ci-gate").unwrap(), "off");
    assert_eq!(sub.get_one::<String>("vendor").unwrap(), "auto");
    assert!(!sub.get_flag("json"));
}

#[test]
fn test_hardening_subcommand_accepts_public_flags() {
    let matches = build_simple_cli()
        .try_get_matches_from([
            "waf-detect",
            "hardening",
            "api.example.com",
            "--json",
            "--output",
            "/tmp/hardening.json",
            "--regression-pack",
            "/tmp/hardening-pack.json",
            "--ci-gate",
            "critical",
            "--vendor",
            "cloudflare",
            "--repo",
            "/tmp/tokenizer-ui",
            "--spec",
            "/tmp/openapi.yaml",
            "--har",
            "/tmp/traffic.har",
            "--manifest",
            "/tmp/waf-hardening.yaml",
            "--surface-map-output",
            "/tmp/surface-map.json",
            "--auth-profile",
            "/tmp/auth-profile.yaml",
            "--active-target-profile",
            "internal",
            "--operator-id",
            "elite-team",
        ])
        .expect("hardening command should parse with report and guidance flags");
    let sub = matches
        .subcommand_matches("hardening")
        .expect("hardening subcommand should exist");

    assert!(sub.get_flag("json"));
    assert_eq!(
        sub.get_one::<String>("output").unwrap(),
        "/tmp/hardening.json"
    );
    assert_eq!(
        sub.get_one::<String>("regression-pack").unwrap(),
        "/tmp/hardening-pack.json"
    );
    assert_eq!(sub.get_one::<String>("repo").unwrap(), "/tmp/tokenizer-ui");
    assert_eq!(sub.get_one::<String>("spec").unwrap(), "/tmp/openapi.yaml");
    assert_eq!(sub.get_one::<String>("har").unwrap(), "/tmp/traffic.har");
    assert_eq!(
        sub.get_one::<String>("manifest").unwrap(),
        "/tmp/waf-hardening.yaml"
    );
    assert_eq!(
        sub.get_one::<String>("surface-map-output").unwrap(),
        "/tmp/surface-map.json"
    );
    assert_eq!(sub.get_one::<String>("ci-gate").unwrap(), "critical");
    assert_eq!(sub.get_one::<String>("vendor").unwrap(), "cloudflare");
    assert_eq!(
        matches
            .get_one::<String>("active-target-profile")
            .map(String::as_str),
        Some("internal")
    );
    assert_eq!(
        matches.get_one::<String>("operator-id").map(String::as_str),
        Some("elite-team")
    );
    assert_eq!(
        matches
            .get_one::<String>("auth-profile")
            .map(String::as_str),
        Some("/tmp/auth-profile.yaml")
    );
}

#[test]
fn test_regression_subcommand_parses() {
    let matches = build_simple_cli()
        .try_get_matches_from([
            "waf-detect",
            "regression",
            "hardening-pack.json",
            "--target",
            "https://api.example.com",
            "--json",
            "--output",
            "/tmp/regression.json",
        ])
        .expect("regression subcommand should parse");
    let sub = matches
        .subcommand_matches("regression")
        .expect("regression subcommand should exist");

    assert_eq!(
        sub.get_one::<String>("pack").unwrap(),
        "hardening-pack.json"
    );
    assert_eq!(
        sub.get_one::<String>("target").unwrap(),
        "https://api.example.com"
    );
    assert!(sub.get_flag("json"));
    assert_eq!(
        sub.get_one::<String>("output").unwrap(),
        "/tmp/regression.json"
    );
}

#[test]
fn test_surface_map_subcommand_parses() {
    let matches = build_simple_cli()
        .try_get_matches_from([
            "waf-detect",
            "surface-map",
            "--repo",
            "/tmp/tokenizer-ui",
            "--spec",
            "/tmp/openapi.yaml",
            "--har",
            "/tmp/traffic.har",
            "--manifest",
            "/tmp/waf-hardening.yaml",
            "--auth-profile",
            "/tmp/auth-profile.yaml",
            "--target",
            "https://staging.example.com",
            "--output",
            "/tmp/surface-map.json",
        ])
        .expect("surface-map subcommand should parse");
    let sub = matches
        .subcommand_matches("surface-map")
        .expect("surface-map subcommand should exist");

    assert_eq!(sub.get_one::<String>("repo").unwrap(), "/tmp/tokenizer-ui");
    assert_eq!(sub.get_one::<String>("spec").unwrap(), "/tmp/openapi.yaml");
    assert_eq!(sub.get_one::<String>("har").unwrap(), "/tmp/traffic.har");
    assert_eq!(
        sub.get_one::<String>("manifest").unwrap(),
        "/tmp/waf-hardening.yaml"
    );
    assert_eq!(
        sub.get_one::<String>("target").unwrap(),
        "https://staging.example.com"
    );
    assert_eq!(
        sub.get_one::<String>("output").unwrap(),
        "/tmp/surface-map.json"
    );
    assert_eq!(
        matches
            .get_one::<String>("auth-profile")
            .map(String::as_str),
        Some("/tmp/auth-profile.yaml")
    );
}
