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
