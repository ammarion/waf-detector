#!/usr/bin/env bash
set -euo pipefail

BIN="${BIN:-./target/debug/waf-detect}"
CORPUS="${1:-benchmark_corpus.json}"
FIXTURES="${2:-tests/fixtures/benchmark}"
RUNS="${RUNS:-3}"

if [[ ! -x "$BIN" ]]; then
  echo "error: binary not found or not executable: $BIN" >&2
  exit 1
fi

if [[ ! -f "$CORPUS" ]]; then
  echo "error: corpus not found: $CORPUS" >&2
  exit 1
fi

if [[ ! -d "$FIXTURES" ]]; then
  echo "error: fixture directory not found: $FIXTURES" >&2
  exit 1
fi

hashes=()
scan_p95_values=()

for i in $(seq 1 "$RUNS"); do
  report_file="$(mktemp -t waf-bench-report.XXXXXX.json)"
  perf_file="$(mktemp -t waf-bench-perf.XXXXXX.json)"
  log_file="$(mktemp -t waf-bench-log.XXXXXX.txt)"

  WAF_DETECTOR_FIXTURE_MODE=1 \
  "$BIN" \
    --benchmark "$CORPUS" \
    --benchmark-mode fixture \
    --benchmark-fixtures "$FIXTURES" \
    --benchmark-workers 1 \
    --benchmark-output "$report_file" \
    --perf-report "$perf_file" >"$log_file" 2>&1

  hash="$(python3 - "$report_file" <<'PY'
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    data = json.load(f)
print(data.get('determinism_hash', ''))
PY
)"
  scan_p95="$(python3 - "$perf_file" <<'PY'
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    data = json.load(f)
print(int(data.get('scan_p95_ms', 0)))
PY
)"

  hashes+=("$hash")
  scan_p95_values+=("$scan_p95")
  echo "run=$i determinism_hash=$hash scan_p95_ms=$scan_p95"
done

first_hash="${hashes[0]}"
for hash in "${hashes[@]}"; do
  if [[ "$hash" != "$first_hash" ]]; then
    echo "determinism gate failed: hashes differ across runs: ${hashes[*]}" >&2
    exit 1
  fi
done

for value in "${scan_p95_values[@]}"; do
  if (( value > 1200 )); then
    echo "scan p95 gate failed: value=${value}ms exceeds 1200ms" >&2
    exit 1
  fi
done

echo "determinism and scan p95 gates passed across $RUNS run(s)."
