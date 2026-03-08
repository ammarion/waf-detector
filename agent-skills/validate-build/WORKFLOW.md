# Validate Build Workflow

Use this workflow for final validation before merge or push.

## Steps

1. Verify skill wrappers if any shared workflow or wrapper changed

```bash
python3 agent-skills/check_wrappers.py
```

2. Formatting

```bash
cargo fmt --check
```

3. Lint

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

4. Tests

```bash
cargo test -q
```

5. Release build

```bash
cargo build --release
```

## Failure Handling

- If formatting fails, run `cargo fmt` and report what changed
- If clippy fails, report file locations and warnings
- If tests fail, report failing test names and the important error output
- If release build fails, report the compiler error and stop

## Output

Report pass or fail for each step with counts where available.
