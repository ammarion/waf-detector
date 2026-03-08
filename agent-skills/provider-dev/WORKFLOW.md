# Provider Dev Workflow

Use this workflow when adding a new WAF/CDN provider or extending detection logic.

## Use Cases

- "Add detection for Akamai" (or another provider)
- "Implement a new WAF provider"
- "Extend the provider system"

## Prerequisites

- Read `CLAUDE.md` "Provider Implementation Pattern" and "Architecture Overview"
- Existing providers in `src/providers/` (cloudflare, akamai, aws, etc.) are reference implementations

## Steps

1. **Create provider file**

   Create `src/providers/<name>.rs` (e.g. `src/providers/cloudflare.rs`).

2. **Implement DetectionProvider trait**

   Implement from `crate::lib`:
   - `name()`, `version()`, `description()`, `provider_type()`, `confidence_base()`, `priority()`, `enabled()`
   - `detect()` — main detection entry
   - `passive_detect()` — headers/body only
   - `active_detect()` — probes if needed

   Define detection methods: passive (headers/body), active (probes), DNS where applicable.

3. **Register in providers/mod.rs**

   - Add `pub mod <name>;`
   - Add variant to `Provider` enum
   - Add match arms for all Provider methods (or use macro if available)

4. **Register in SimpleCliApp**

   In `src/cli/mod.rs`, find `SimpleCliApp::new()` and add the provider to the registry.

5. **Add tests**

   Add unit tests in `src/providers/<name>.rs` (e.g. `mod tests`) or in `tests/` directory.
   Run `cargo test --lib` to verify.

## Validation

```bash
cargo build
cargo test --lib
cargo clippy -- -D warnings
```

## Notes

- Follow patterns from existing providers (e.g. cloudflare, aws)
- Use `Evidence` and `DetectionResult` from lib
- Consent is not required for detection; it is required for effectiveness, enforcement, and behavioral testing
