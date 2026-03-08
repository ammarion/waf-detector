use std::path::PathBuf;

use waf_detector::surface::{CompilerInputs, RoutePriority, SurfaceMapCompiler};

#[test]
fn test_fixture_frontend_repo_produces_route_aware_surface_map() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture_repo = root.join("tests/fixtures/tokenizer_ui_mock");
    let fixture_spec = root.join("tests/fixtures/tokenizer_ui_mock.open_api.yaml");
    let fixture_har = root.join("tests/fixtures/tokenizer_ui_mock.traffic.har");

    // Fixtures are local-only (gitignored). Skip in CI where they don't exist.
    if !fixture_repo.exists() {
        eprintln!("skipping: fixture repo not present at {}", fixture_repo.display());
        return;
    }

    let surface_map = SurfaceMapCompiler::new()
        .compile(CompilerInputs {
            target_url: "https://staging.example.com".to_string(),
            repo: Some(fixture_repo.display().to_string()),
            spec: Some(fixture_spec),
            har: Some(fixture_har),
            manifest: None,
        })
        .expect("fixture surface map should compile");

    assert!(!surface_map.endpoints.is_empty());
    assert!(surface_map.summary.sources.contains_key("frontend_repo"));
    assert!(surface_map.summary.sources.contains_key("openapi"));
    assert!(surface_map.summary.sources.contains_key("har"));

    let tokenize = surface_map
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path_template == "/api/tokenize")
        .expect("tokenize endpoint should be discovered");
    assert!(tokenize.methods.contains(&"POST".to_string()));
    assert!(tokenize.priority.rank() >= RoutePriority::High.rank());
    assert!(tokenize
        .discovery_sources
        .iter()
        .any(|source| source.as_str() == "openapi"));
}
