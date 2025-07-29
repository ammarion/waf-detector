#!/bin/bash
# Comprehensive validation test runner for WAF Detector

set -e

echo "=========================================="
echo "WAF Detector Comprehensive Validation"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Build the project
echo -e "${YELLOW}Building WAF Detector...${NC}"
cargo build --release
echo -e "${GREEN}✓ Build complete${NC}"
echo ""

# Run Rust unit tests
echo -e "${YELLOW}Running Rust unit tests...${NC}"
cargo test --all
echo -e "${GREEN}✓ Rust tests passed${NC}"
echo ""

# Run CI validation
echo -e "${YELLOW}Running CI validation tests...${NC}"
python3 ci_validation.py ./target/release/waf-detector
CI_EXIT_CODE=$?
if [ $CI_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ CI validation passed${NC}"
else
    echo -e "${RED}✗ CI validation failed${NC}"
fi
echo ""

# Run comprehensive accuracy validation
echo -e "${YELLOW}Running comprehensive accuracy validation...${NC}"
python3 accuracy_validation.py || true
echo -e "${GREEN}✓ Accuracy validation complete (see validation_report.md)${NC}"
echo ""

# Run header comparison tests
echo -e "${YELLOW}Running header comparison tests...${NC}"
python3 header_comparison_test.py || true
echo -e "${GREEN}✓ Header comparison complete (see header_comparison_report.md)${NC}"
echo ""

# Summary
echo "=========================================="
echo "Validation Summary"
echo "=========================================="
echo ""

# Check if validation passed
if [ $CI_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✅ VALIDATION PASSED${NC}"
    echo ""
    echo "Reports generated:"
    echo "  - ci_validation_results.json"
    echo "  - validation_report.md"
    echo "  - validation_results.json"
    echo "  - validation_metrics.json"
    echo "  - header_comparison_report.md"
    echo "  - header_comparison_results.json"
    echo "  - missed_header_patterns.json"
else
    echo -e "${RED}❌ VALIDATION FAILED${NC}"
    echo ""
    echo "Please check the reports for details."
    exit 1
fi

# Display key metrics if available
if [ -f validation_metrics.json ]; then
    echo ""
    echo "Key Metrics:"
    python3 -c "
import json
with open('validation_metrics.json', 'r') as f:
    metrics = json.load(f)
    if 'combined' in metrics:
        print(f'  Overall Accuracy: {metrics[\"combined\"][\"accuracy\"]*100:.1f}%')
        print(f'  Overall F1 Score: {metrics[\"combined\"][\"f1_score\"]*100:.1f}%')
    if 'waf' in metrics:
        print(f'  WAF F1 Score: {metrics[\"waf\"][\"f1_score\"]*100:.1f}%')
    if 'cdn' in metrics:
        print(f'  CDN F1 Score: {metrics[\"cdn\"][\"f1_score\"]*100:.1f}%')
" || true
fi