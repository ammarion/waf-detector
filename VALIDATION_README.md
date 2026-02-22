# WAF Detector Validation System

This directory contains a comprehensive validation system for the WAF Detector project to ensure accuracy, reliability, and prevent regressions.

## Overview

The validation system consists of several components:

1. **Accuracy Validation** (`accuracy_validation.py`) - Tests detection accuracy against known WAF/CDN providers
2. **Header Comparison** (`header_comparison_test.py`) - Compares HTTP header analysis with detection results
3. **CI Validation** (`ci_validation.py`) - Lightweight validation for CI/CD pipelines
4. **Provider Tests** - Unit tests for each provider implementation

## Quick Start

Run all validation tests:
```bash
./run_validation_tests.sh
```

## Components

### 1. Accuracy Validation

Tests the detector against a ground truth dataset of known WAF/CDN configurations.

```bash
python3 accuracy_validation.py
```

**Features:**
- Tests against 20+ known sites
- Calculates precision, recall, F1 score
- Identifies false positives and false negatives
- Generates detailed reports

**Output Files:**
- `validation_report.md` - Human-readable report
- `validation_results.json` - Detailed test results
- `validation_metrics.json` - Calculated metrics

### 2. Header Comparison Test

Systematically compares actual HTTP headers with detection results to identify missed patterns.

```bash
python3 header_comparison_test.py
```

**Features:**
- Fetches actual headers from test sites
- Compares with WAF detector results
- Identifies header patterns that might be missed
- Helps improve detection rules

**Output Files:**
- `header_comparison_report.md` - Comparison report
- `header_comparison_results.json` - Raw results
- `missed_header_patterns.json` - Patterns found but not detected

### 3. CI Validation

Lightweight validation designed for CI/CD pipelines with strict pass/fail criteria.

```bash
python3 ci_validation.py ./target/release/waf-detector
```

**Features:**
- Required test cases that must pass
- Performance benchmarks
- Minimum accuracy thresholds
- Exit code indicates pass/fail

**Requirements:**
- Overall accuracy ≥ 85%
- WAF precision ≥ 90%
- WAF recall ≥ 80%
- Average detection time ≤ 2s
- Max detection time ≤ 5s

### 4. Provider Unit Tests

Rust unit tests for each provider implementation.

```bash
cargo test --all
```

**Test Files:**
- `tests/azure_provider_test.rs` - Azure provider tests
- `tests/f5_provider_test.rs` - F5 provider tests
- `tests/akamai_provider_test.rs` - Akamai provider tests
- `tests/aws_provider_test.rs` - AWS provider tests
- Other provider tests...

## GitHub Actions Integration

The validation system is integrated with GitHub Actions:

- Runs on every push to main/develop
- Runs on all pull requests
- Daily scheduled runs to catch external changes
- Posts results as PR comments

See `.github/workflows/accuracy_validation.yml`

## Adding New Test Cases

### Ground Truth Data

Add new test cases to `accuracy_validation.py`:

```python
GroundTruthEntry(
    url="https://example.com",
    waf_provider="ProviderName",  # or None
    cdn_provider="ProviderName",  # or None
    confidence_level=0.90,
    notes="Description of the site",
    expected_headers={"header-name": "pattern"}
)
```

### Header Patterns

Add new header patterns to `header_comparison_test.py`:

```python
HEADER_PATTERNS = {
    "ProviderName": {
        "headers": {
            "x-provider-header": r"pattern.*",
        },
        "cookies": {
            "provider_cookie": r".*",
        }
    }
}
```

## Interpreting Results

### Accuracy Metrics

- **Accuracy**: Overall correctness (TP + TN) / Total
- **Precision**: True Positives / (True Positives + False Positives)
- **Recall**: True Positives / (True Positives + False Negatives)
- **F1 Score**: Harmonic mean of precision and recall

### Target Metrics

We aim for:
- Overall accuracy > 85%
- Precision > 90% (few false positives)
- Recall > 80% (catch most WAFs/CDNs)
- F1 Score > 85%

### Common Issues

1. **False Positives**: Detector identifies WAF/CDN that isn't there
   - Usually due to overly broad patterns
   - Check header comparison results

2. **False Negatives**: Detector misses WAF/CDN that is present
   - Missing header patterns
   - Need to add detection rules

3. **Performance Issues**: Detection takes too long
   - Check network timeouts
   - Optimize active detection

## Development Workflow

1. Make changes to providers or detection logic
2. Run validation tests locally: `./run_validation_tests.sh`
3. Fix any failing tests
4. Commit and push - CI will validate again
5. Check PR comments for validation results

### Enforcement / Behavioral Testing Validation Notes

- Enforcement and behavioral tests require **consent and authorized targets**.
- Automated tests are limited to unit coverage; end-to-end runs should be validated manually.
- Validate enforcement replay plan and export checks via CLI (`va --replay`, `va --replay-csv`).
- Keep `cargo test` green after any probe or replay-plan changes.

## Troubleshooting

### Python Dependencies

Install required packages:
```bash
pip install aiohttp pyyaml
```

### Build Issues

Ensure Rust is installed and build the project:
```bash
cargo build --release
```

### Network Issues

Some tests require internet access. If behind a proxy, set:
```bash
export HTTP_PROXY=http://proxy:port
export HTTPS_PROXY=http://proxy:port
```

## Contributing

When adding new providers:
1. Create provider implementation in `src/providers/`
2. Add unit tests in `tests/`
3. Update ground truth data in validation scripts
4. Run full validation suite
5. Ensure all tests pass before submitting PR
