use crate::engine::DetectionEngine;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkMode {
    Live,
    Fixture,
}

#[derive(Debug, Clone)]
pub struct BenchmarkOptions {
    pub mode: BenchmarkMode,
    pub fixtures_dir: Option<PathBuf>,
}

impl Default for BenchmarkOptions {
    fn default() -> Self {
        Self {
            mode: BenchmarkMode::Live,
            fixtures_dir: None,
        }
    }
}

/// Corpus file format: JSON with labeled entries for benchmark evaluation.
#[derive(Debug, Deserialize)]
pub struct BenchmarkCorpus {
    #[allow(dead_code)]
    pub version: Option<String>,
    pub entries: Vec<CorpusEntry>,
}

#[derive(Debug, Deserialize)]
pub struct CorpusEntry {
    pub url: String,
    pub expected_waf: Option<String>,
    pub expected_cdn: Option<String>,
    #[allow(dead_code)]
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FixtureCorpus {
    responses: HashMap<String, FixtureDetection>,
}

#[derive(Debug, Deserialize)]
struct FixtureDetection {
    detected_waf: Option<String>,
    detected_cdn: Option<String>,
    #[serde(default)]
    detection_time_ms: u64,
    #[serde(default)]
    error: Option<String>,
}

/// Per-entry result from running detection against a corpus entry.
#[derive(Debug, Serialize, Clone)]
pub struct EntryResult {
    pub url: String,
    pub expected_waf: Option<String>,
    pub detected_waf: Option<String>,
    pub waf_correct: bool,
    pub expected_cdn: Option<String>,
    pub detected_cdn: Option<String>,
    pub cdn_correct: bool,
    pub detection_time_ms: u64,
    pub error: Option<String>,
}

/// Per-provider precision/recall/F1 metrics.
#[derive(Debug, Clone, Serialize)]
pub struct ProviderMetrics {
    pub provider: String,
    pub true_positives: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
}

/// Overall benchmark report.
#[derive(Debug, Serialize)]
pub struct BenchmarkReport {
    pub corpus_size: usize,
    pub entries_scanned: usize,
    pub entries_errored: usize,
    pub network_error_count: usize,
    pub fixture_mode: bool,
    pub determinism_hash: String,
    pub total_time_ms: u64,
    pub waf_accuracy: f64,
    pub cdn_accuracy: f64,
    pub overall_accuracy: f64,
    pub waf_provider_metrics: Vec<ProviderMetrics>,
    pub cdn_provider_metrics: Vec<ProviderMetrics>,
    pub confusion_matrix_waf: ConfusionMatrix,
    pub confusion_matrix_cdn: ConfusionMatrix,
    pub entry_results: Vec<EntryResult>,
}

/// Confusion matrix: rows = actual, columns = predicted.
#[derive(Debug, Serialize)]
pub struct ConfusionMatrix {
    /// Sorted list of labels (providers + "None")
    pub labels: Vec<String>,
    /// matrix[actual_idx][predicted_idx] = count
    pub matrix: Vec<Vec<usize>>,
}

impl ConfusionMatrix {
    fn new(labels: Vec<String>) -> Self {
        let n = labels.len();
        Self {
            labels,
            matrix: vec![vec![0usize; n]; n],
        }
    }

    fn record(&mut self, actual: &str, predicted: &str) {
        let actual_idx = self.labels.iter().position(|l| l == actual);
        let predicted_idx = self.labels.iter().position(|l| l == predicted);
        if let (Some(a), Some(p)) = (actual_idx, predicted_idx) {
            self.matrix[a][p] += 1;
        }
    }
}

/// Run detection benchmark against a labeled corpus.
#[allow(dead_code)]
pub async fn run_benchmark(
    engine: &DetectionEngine,
    corpus: &BenchmarkCorpus,
    workers: usize,
) -> Result<BenchmarkReport> {
    run_benchmark_with_options(engine, corpus, workers, &BenchmarkOptions::default()).await
}

fn load_fixture_corpus(fixtures_dir: &Path) -> Result<FixtureCorpus> {
    let path = fixtures_dir.join("fixtures.json");
    let raw = std::fs::read_to_string(&path).map_err(|err| {
        anyhow::anyhow!(
            "failed to read fixture corpus at {}: {}",
            path.display(),
            err
        )
    })?;
    let corpus = serde_json::from_str::<FixtureCorpus>(&raw).map_err(|err| {
        anyhow::anyhow!(
            "failed to parse fixture corpus at {}: {}",
            path.display(),
            err
        )
    })?;
    Ok(corpus)
}

fn deterministic_hash(entry_results: &[EntryResult], fixture_mode: bool) -> String {
    let mut rows: Vec<String> = entry_results
        .iter()
        .map(|entry| {
            format!(
                "{}|{:?}|{:?}|{:?}|{:?}|{}|{}|{}",
                entry.url,
                entry.expected_waf,
                entry.detected_waf,
                entry.expected_cdn,
                entry.detected_cdn,
                entry.waf_correct,
                entry.cdn_correct,
                entry.error.clone().unwrap_or_default()
            )
        })
        .collect();
    rows.sort();
    let marker = if fixture_mode { "fixture" } else { "live" };
    let payload = format!("{marker}\n{}", rows.join("\n"));
    format!("{:x}", md5::compute(payload.as_bytes()))
}

pub async fn run_benchmark_with_options(
    engine: &DetectionEngine,
    corpus: &BenchmarkCorpus,
    workers: usize,
    options: &BenchmarkOptions,
) -> Result<BenchmarkReport> {
    let total_start = Instant::now();

    // Build entry results
    let mut entry_results = Vec::with_capacity(corpus.entries.len());
    let mut entries_errored = 0usize;
    let fixture_mode = options.mode == BenchmarkMode::Fixture;

    if fixture_mode {
        let fixture_dir = options.fixtures_dir.as_ref().ok_or_else(|| {
            anyhow::anyhow!("benchmark fixture mode requires --benchmark-fixtures <DIR>")
        })?;
        let fixture = load_fixture_corpus(fixture_dir)?;
        for entry in &corpus.entries {
            let fixture_result = fixture.responses.get(&entry.url);
            if let Some(found) = fixture_result {
                let expected_waf = entry.expected_waf.as_deref().map(normalize_provider_name);
                let expected_cdn = entry.expected_cdn.as_deref().map(normalize_provider_name);
                let detected_waf = found.detected_waf.as_deref().map(normalize_provider_name);
                let detected_cdn = found.detected_cdn.as_deref().map(normalize_provider_name);
                let waf_correct = expected_waf == detected_waf;
                let cdn_correct = expected_cdn == detected_cdn;
                if found.error.is_some() {
                    entries_errored += 1;
                }
                entry_results.push(EntryResult {
                    url: entry.url.clone(),
                    expected_waf: entry.expected_waf.clone(),
                    detected_waf: found.detected_waf.clone(),
                    waf_correct,
                    expected_cdn: entry.expected_cdn.clone(),
                    detected_cdn: found.detected_cdn.clone(),
                    cdn_correct,
                    detection_time_ms: found.detection_time_ms,
                    error: found.error.clone(),
                });
                crate::perf::record(
                    crate::perf::PerfKind::Scan,
                    found.detection_time_ms,
                    crate::perf::PerfMode::Fixture,
                );
            } else {
                entries_errored += 1;
                entry_results.push(EntryResult {
                    url: entry.url.clone(),
                    expected_waf: entry.expected_waf.clone(),
                    detected_waf: None,
                    waf_correct: false,
                    expected_cdn: entry.expected_cdn.clone(),
                    detected_cdn: None,
                    cdn_correct: false,
                    detection_time_ms: 0,
                    error: Some("Missing fixture response for URL".to_string()),
                });
            }
        }
    } else {
        // Run detection on all entries via batch
        let urls: Vec<&str> = corpus.entries.iter().map(|e| e.url.as_str()).collect();
        let batch_results = engine.detect_batch(&urls, workers).await?;
        for entry in &corpus.entries {
            let result = batch_results.get(&entry.url);
            match result {
                Some(detection) => {
                    // detect_batch synthesizes empty results for failures
                    // (detection_time_ms == 0, no evidence, no detections)
                    let is_failed = detection.detection_time_ms == 0
                        && detection.evidence.is_empty()
                        && detection.detected_waf.is_none()
                        && detection.detected_cdn.is_none();

                    if is_failed {
                        entries_errored += 1;
                        entry_results.push(EntryResult {
                            url: entry.url.clone(),
                            expected_waf: entry.expected_waf.clone(),
                            detected_waf: None,
                            waf_correct: false,
                            expected_cdn: entry.expected_cdn.clone(),
                            detected_cdn: None,
                            cdn_correct: false,
                            detection_time_ms: 0,
                            error: Some("Detection failed (no HTTP response)".to_string()),
                        });
                    } else {
                        let detected_waf = detection.waf_name().map(normalize_provider_name);
                        let detected_cdn = detection.cdn_name().map(normalize_provider_name);
                        let expected_waf =
                            entry.expected_waf.as_deref().map(normalize_provider_name);
                        let expected_cdn =
                            entry.expected_cdn.as_deref().map(normalize_provider_name);

                        let waf_correct = expected_waf == detected_waf;
                        let cdn_correct = expected_cdn == detected_cdn;

                        entry_results.push(EntryResult {
                            url: entry.url.clone(),
                            expected_waf: entry.expected_waf.clone(),
                            detected_waf: detection.waf_name().map(String::from),
                            waf_correct,
                            expected_cdn: entry.expected_cdn.clone(),
                            detected_cdn: detection.cdn_name().map(String::from),
                            cdn_correct,
                            detection_time_ms: detection.detection_time_ms,
                            error: None,
                        });
                    }
                }
                None => {
                    entries_errored += 1;
                    entry_results.push(EntryResult {
                        url: entry.url.clone(),
                        expected_waf: entry.expected_waf.clone(),
                        detected_waf: None,
                        waf_correct: false,
                        expected_cdn: entry.expected_cdn.clone(),
                        detected_cdn: None,
                        cdn_correct: false,
                        detection_time_ms: 0,
                        error: Some("Detection returned no result".to_string()),
                    });
                }
            }
        }
    }

    // Compute accuracy
    let entries_scanned = entry_results.len();
    let waf_correct = entry_results.iter().filter(|e| e.waf_correct).count();
    let cdn_correct = entry_results.iter().filter(|e| e.cdn_correct).count();
    let both_correct = entry_results
        .iter()
        .filter(|e| e.waf_correct && e.cdn_correct)
        .count();

    let waf_accuracy = if entries_scanned > 0 {
        waf_correct as f64 / entries_scanned as f64
    } else {
        0.0
    };
    let cdn_accuracy = if entries_scanned > 0 {
        cdn_correct as f64 / entries_scanned as f64
    } else {
        0.0
    };
    let overall_accuracy = if entries_scanned > 0 {
        both_correct as f64 / entries_scanned as f64
    } else {
        0.0
    };

    // Compute per-provider metrics and confusion matrices
    let waf_provider_metrics = compute_provider_metrics(&entry_results, DetectionType::Waf);
    let cdn_provider_metrics = compute_provider_metrics(&entry_results, DetectionType::Cdn);
    let confusion_matrix_waf = build_confusion_matrix(&entry_results, DetectionType::Waf);
    let confusion_matrix_cdn = build_confusion_matrix(&entry_results, DetectionType::Cdn);

    let total_time_ms = total_start.elapsed().as_millis() as u64;
    let network_error_count = entry_results.iter().filter(|r| r.error.is_some()).count();
    let determinism_hash = deterministic_hash(&entry_results, fixture_mode);

    Ok(BenchmarkReport {
        corpus_size: corpus.entries.len(),
        entries_scanned,
        entries_errored,
        network_error_count,
        fixture_mode,
        determinism_hash,
        total_time_ms,
        waf_accuracy,
        cdn_accuracy,
        overall_accuracy,
        waf_provider_metrics,
        cdn_provider_metrics,
        confusion_matrix_waf,
        confusion_matrix_cdn,
        entry_results,
    })
}

fn normalize_provider_name(name: &str) -> String {
    name.to_lowercase()
}

#[derive(Clone, Copy)]
enum DetectionType {
    Waf,
    Cdn,
}

fn compute_provider_metrics(
    results: &[EntryResult],
    detection_type: DetectionType,
) -> Vec<ProviderMetrics> {
    // Collect all provider names mentioned in expected or detected
    let mut providers: HashMap<String, (usize, usize, usize)> = HashMap::new(); // (TP, FP, FN)

    for entry in results {
        let (expected, detected) = match detection_type {
            DetectionType::Waf => (
                entry.expected_waf.as_deref().map(normalize_provider_name),
                entry.detected_waf.as_deref().map(normalize_provider_name),
            ),
            DetectionType::Cdn => (
                entry.expected_cdn.as_deref().map(normalize_provider_name),
                entry.detected_cdn.as_deref().map(normalize_provider_name),
            ),
        };

        match (expected, detected) {
            (Some(exp), Some(det)) if exp == det => {
                // True positive for this provider
                providers.entry(exp).or_default().0 += 1;
            }
            (Some(exp), Some(det)) => {
                // False negative for expected, false positive for detected
                providers.entry(exp).or_default().2 += 1;
                providers.entry(det).or_default().1 += 1;
            }
            (Some(exp), None) => {
                // False negative
                providers.entry(exp).or_default().2 += 1;
            }
            (None, Some(det)) => {
                // False positive
                providers.entry(det).or_default().1 += 1;
            }
            (None, None) => {
                // True negative — correct, but no provider-specific tracking needed
            }
        }
    }

    let mut metrics: Vec<ProviderMetrics> = providers
        .into_iter()
        .map(|(provider, (tp, fp, r#fn))| {
            let precision = if tp + fp > 0 {
                tp as f64 / (tp + fp) as f64
            } else {
                0.0
            };
            let recall = if tp + r#fn > 0 {
                tp as f64 / (tp + r#fn) as f64
            } else {
                0.0
            };
            let f1 = if precision + recall > 0.0 {
                2.0 * precision * recall / (precision + recall)
            } else {
                0.0
            };
            ProviderMetrics {
                provider,
                true_positives: tp,
                false_positives: fp,
                false_negatives: r#fn,
                precision,
                recall,
                f1,
            }
        })
        .collect();

    metrics.sort_by(|a, b| b.f1.partial_cmp(&a.f1).unwrap_or(std::cmp::Ordering::Equal));
    metrics
}

fn build_confusion_matrix(
    results: &[EntryResult],
    detection_type: DetectionType,
) -> ConfusionMatrix {
    let none_label = "None".to_string();

    // Collect all unique labels
    let mut label_set = std::collections::BTreeSet::new();
    for entry in results {
        let (expected, detected) = match detection_type {
            DetectionType::Waf => (&entry.expected_waf, &entry.detected_waf),
            DetectionType::Cdn => (&entry.expected_cdn, &entry.detected_cdn),
        };
        label_set.insert(expected.clone().unwrap_or_else(|| none_label.clone()));
        label_set.insert(detected.clone().unwrap_or_else(|| none_label.clone()));
    }

    let labels: Vec<String> = label_set.into_iter().collect();
    let mut cm = ConfusionMatrix::new(labels);

    for entry in results {
        let (expected, detected) = match detection_type {
            DetectionType::Waf => (&entry.expected_waf, &entry.detected_waf),
            DetectionType::Cdn => (&entry.expected_cdn, &entry.detected_cdn),
        };
        let actual = expected.as_deref().unwrap_or("None");
        let predicted = detected.as_deref().unwrap_or("None");
        cm.record(actual, predicted);
    }

    cm
}

impl BenchmarkReport {
    pub fn print_summary(&self) {
        println!("═══════════════════════════════════════════════════════════════");
        println!("                    BENCHMARK RESULTS");
        println!("═══════════════════════════════════════════════════════════════");
        println!();
        println!(
            "  Corpus:    {} entries ({} scanned, {} errors)",
            self.corpus_size, self.entries_scanned, self.entries_errored
        );
        println!(
            "  Mode:      {}",
            if self.fixture_mode { "fixture" } else { "live" }
        );
        println!("  Net Errors: {}", self.network_error_count);
        println!("  Hash:      {}", self.determinism_hash);
        println!("  Time:      {} ms", self.total_time_ms);
        println!();
        println!("  WAF Accuracy:     {:.1}%", self.waf_accuracy * 100.0);
        println!("  CDN Accuracy:     {:.1}%", self.cdn_accuracy * 100.0);
        println!("  Overall Accuracy: {:.1}%", self.overall_accuracy * 100.0);
        println!();

        // WAF provider metrics
        if !self.waf_provider_metrics.is_empty() {
            println!("  WAF Per-Provider Metrics:");
            println!(
                "  {:<15} {:>4} {:>4} {:>4} {:>8} {:>8} {:>8}",
                "Provider", "TP", "FP", "FN", "Prec", "Recall", "F1"
            );
            println!("  {}", "-".repeat(60));
            for m in &self.waf_provider_metrics {
                println!(
                    "  {:<15} {:>4} {:>4} {:>4} {:>7.1}% {:>7.1}% {:>7.1}%",
                    m.provider,
                    m.true_positives,
                    m.false_positives,
                    m.false_negatives,
                    m.precision * 100.0,
                    m.recall * 100.0,
                    m.f1 * 100.0,
                );
            }
            println!();
        }

        // CDN provider metrics
        if !self.cdn_provider_metrics.is_empty() {
            println!("  CDN Per-Provider Metrics:");
            println!(
                "  {:<15} {:>4} {:>4} {:>4} {:>8} {:>8} {:>8}",
                "Provider", "TP", "FP", "FN", "Prec", "Recall", "F1"
            );
            println!("  {}", "-".repeat(60));
            for m in &self.cdn_provider_metrics {
                println!(
                    "  {:<15} {:>4} {:>4} {:>4} {:>7.1}% {:>7.1}% {:>7.1}%",
                    m.provider,
                    m.true_positives,
                    m.false_positives,
                    m.false_negatives,
                    m.precision * 100.0,
                    m.recall * 100.0,
                    m.f1 * 100.0,
                );
            }
            println!();
        }

        // Confusion matrix (WAF)
        self.print_confusion_matrix("WAF", &self.confusion_matrix_waf);
        self.print_confusion_matrix("CDN", &self.confusion_matrix_cdn);

        // Misclassified entries
        let misses: Vec<&EntryResult> = self
            .entry_results
            .iter()
            .filter(|e| !e.waf_correct || !e.cdn_correct)
            .collect();
        if !misses.is_empty() {
            println!("  Misclassified Entries:");
            for entry in &misses {
                let waf_flag = if entry.waf_correct { " " } else { "W" };
                let cdn_flag = if entry.cdn_correct { " " } else { "C" };
                println!(
                    "  [{}{}] {} expected=({}/{}) detected=({}/{})",
                    waf_flag,
                    cdn_flag,
                    entry.url,
                    entry.expected_waf.as_deref().unwrap_or("None"),
                    entry.expected_cdn.as_deref().unwrap_or("None"),
                    entry.detected_waf.as_deref().unwrap_or("None"),
                    entry.detected_cdn.as_deref().unwrap_or("None"),
                );
            }
            println!();
        }

        println!("═══════════════════════════════════════════════════════════════");
    }

    fn print_confusion_matrix(&self, label: &str, cm: &ConfusionMatrix) {
        if cm.labels.is_empty() {
            return;
        }
        println!("  {} Confusion Matrix (actual \\ predicted):", label);
        let col_width = 12;
        // Header row
        print!("  {:<col_width$}", "");
        for l in &cm.labels {
            let short = if l.len() > col_width - 1 {
                &l[..col_width - 1]
            } else {
                l
            };
            print!("{:>col_width$}", short);
        }
        println!();
        // Data rows
        for (i, row_label) in cm.labels.iter().enumerate() {
            let short = if row_label.len() > col_width - 1 {
                &row_label[..col_width - 1]
            } else {
                row_label
            };
            print!("  {:<col_width$}", short);
            for &count in &cm.matrix[i] {
                print!("{:>col_width$}", count);
            }
            println!();
        }
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_provider_name() {
        assert_eq!(normalize_provider_name("CloudFlare"), "cloudflare");
        assert_eq!(normalize_provider_name("AWS"), "aws");
    }

    #[test]
    fn test_provider_metrics_perfect() {
        let results = vec![
            EntryResult {
                url: "https://a.com".into(),
                expected_waf: Some("CloudFlare".into()),
                detected_waf: Some("CloudFlare".into()),
                waf_correct: true,
                expected_cdn: None,
                detected_cdn: None,
                cdn_correct: true,
                detection_time_ms: 100,
                error: None,
            },
            EntryResult {
                url: "https://b.com".into(),
                expected_waf: None,
                detected_waf: None,
                waf_correct: true,
                expected_cdn: None,
                detected_cdn: None,
                cdn_correct: true,
                detection_time_ms: 100,
                error: None,
            },
        ];
        let metrics = compute_provider_metrics(&results, DetectionType::Waf);
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].true_positives, 1);
        assert_eq!(metrics[0].false_positives, 0);
        assert_eq!(metrics[0].false_negatives, 0);
        assert!((metrics[0].f1 - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_provider_metrics_with_false_positive() {
        let results = vec![EntryResult {
            url: "https://a.com".into(),
            expected_waf: None,
            detected_waf: Some("Akamai".into()),
            waf_correct: false,
            expected_cdn: None,
            detected_cdn: None,
            cdn_correct: true,
            detection_time_ms: 100,
            error: None,
        }];
        let metrics = compute_provider_metrics(&results, DetectionType::Waf);
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].provider, "akamai");
        assert_eq!(metrics[0].false_positives, 1);
        assert_eq!(metrics[0].precision, 0.0);
    }

    #[test]
    fn test_confusion_matrix_structure() {
        let results = vec![
            EntryResult {
                url: "https://a.com".into(),
                expected_waf: Some("CloudFlare".into()),
                detected_waf: Some("CloudFlare".into()),
                waf_correct: true,
                expected_cdn: None,
                detected_cdn: None,
                cdn_correct: true,
                detection_time_ms: 100,
                error: None,
            },
            EntryResult {
                url: "https://b.com".into(),
                expected_waf: Some("Akamai".into()),
                detected_waf: Some("CloudFlare".into()),
                waf_correct: false,
                expected_cdn: None,
                detected_cdn: None,
                cdn_correct: true,
                detection_time_ms: 100,
                error: None,
            },
        ];
        let cm = build_confusion_matrix(&results, DetectionType::Waf);
        // Should have Akamai, CloudFlare as labels (sorted)
        assert!(cm.labels.contains(&"Akamai".to_string()));
        assert!(cm.labels.contains(&"CloudFlare".to_string()));
        // Total entries in matrix should sum to 2
        let total: usize = cm.matrix.iter().flat_map(|row| row.iter()).sum();
        assert_eq!(total, 2);
    }

    #[test]
    fn test_determinism_hash_is_order_independent() {
        let a = EntryResult {
            url: "https://a.com".into(),
            expected_waf: Some("CloudFlare".into()),
            detected_waf: Some("CloudFlare".into()),
            waf_correct: true,
            expected_cdn: None,
            detected_cdn: None,
            cdn_correct: true,
            detection_time_ms: 10,
            error: None,
        };
        let b = EntryResult {
            url: "https://b.com".into(),
            expected_waf: None,
            detected_waf: None,
            waf_correct: true,
            expected_cdn: None,
            detected_cdn: None,
            cdn_correct: true,
            detection_time_ms: 15,
            error: None,
        };
        let hash_one = deterministic_hash(&[a.clone(), b.clone()], true);
        let hash_two = deterministic_hash(&[b, a], true);
        assert_eq!(hash_one, hash_two);
        assert!(!hash_one.is_empty());
    }

    #[test]
    fn test_load_fixture_corpus_roundtrip() {
        let temp = tempfile::tempdir().unwrap();
        let fixture_path = temp.path().join("fixtures.json");
        std::fs::write(
            &fixture_path,
            r#"{"responses":{"https://example.com":{"detected_waf":"CloudFlare","detected_cdn":"CloudFlare","detection_time_ms":42}}}"#,
        )
        .unwrap();
        let loaded = load_fixture_corpus(temp.path()).unwrap();
        assert!(loaded.responses.contains_key("https://example.com"));
    }
}
