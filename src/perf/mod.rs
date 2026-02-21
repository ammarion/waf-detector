use crate::PerformanceSnapshot;
use std::cmp;
use std::sync::{Mutex, OnceLock};

const MAX_SAMPLES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerfMode {
    Live,
    Fixture,
}

impl PerfMode {
    fn as_str(self) -> &'static str {
        match self {
            PerfMode::Live => "live",
            PerfMode::Fixture => "fixture",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerfKind {
    Scan,
    Va,
    Va2,
}

#[derive(Debug, Default)]
struct Collector {
    scan_ms: Vec<u64>,
    va_ms: Vec<u64>,
    va2_ms: Vec<u64>,
    mode: String,
}

impl Collector {
    fn push(samples: &mut Vec<u64>, value: u64) {
        samples.push(value);
        if samples.len() > MAX_SAMPLES {
            let drain = samples.len() - MAX_SAMPLES;
            samples.drain(0..drain);
        }
    }

    fn record(&mut self, kind: PerfKind, value_ms: u64, mode: PerfMode) {
        self.mode = mode.as_str().to_string();
        match kind {
            PerfKind::Scan => Self::push(&mut self.scan_ms, value_ms),
            PerfKind::Va => Self::push(&mut self.va_ms, value_ms),
            PerfKind::Va2 => Self::push(&mut self.va2_ms, value_ms),
        }
    }

    fn quantile(values: &[u64], numer: usize, denom: usize) -> u64 {
        if values.is_empty() {
            return 0;
        }
        let mut sorted = values.to_vec();
        sorted.sort_unstable();
        let idx = cmp::min(
            sorted.len() - 1,
            (sorted.len().saturating_sub(1) * numer) / denom,
        );
        sorted[idx]
    }

    fn snapshot(&self) -> PerformanceSnapshot {
        let sample_size = self.scan_ms.len() + self.va_ms.len() + self.va2_ms.len();
        PerformanceSnapshot {
            scan_p95_ms: Self::quantile(&self.scan_ms, 95, 100),
            va_p95_ms: Self::quantile(&self.va_ms, 95, 100),
            va2_p95_ms: Self::quantile(&self.va2_ms, 95, 100),
            scan_p99_ms: Self::quantile(&self.scan_ms, 99, 100),
            va_p99_ms: Self::quantile(&self.va_ms, 99, 100),
            va2_p99_ms: Self::quantile(&self.va2_ms, 99, 100),
            sample_size,
            mode: if self.mode.is_empty() {
                PerfMode::Live.as_str().to_string()
            } else {
                self.mode.clone()
            },
        }
    }
}

fn collector() -> &'static Mutex<Collector> {
    static INSTANCE: OnceLock<Mutex<Collector>> = OnceLock::new();
    INSTANCE.get_or_init(|| Mutex::new(Collector::default()))
}

pub fn record(kind: PerfKind, value_ms: u64, mode: PerfMode) {
    let lock = collector();
    let mut guard = lock.lock().unwrap_or_else(|err| err.into_inner());
    guard.record(kind, value_ms, mode);
}

pub fn snapshot() -> PerformanceSnapshot {
    let lock = collector();
    let guard = lock.lock().unwrap_or_else(|err| err.into_inner());
    guard.snapshot()
}

#[cfg(test)]
pub(crate) fn reset_for_tests() {
    let lock = collector();
    let mut guard = lock.lock().unwrap_or_else(|err| err.into_inner());
    *guard = Collector::default();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_percentiles_and_mode() {
        reset_for_tests();
        for v in 1..=100 {
            record(PerfKind::Scan, v, PerfMode::Fixture);
        }
        for v in 10..=50 {
            record(PerfKind::Va, v, PerfMode::Fixture);
        }
        let snap = snapshot();
        assert_eq!(snap.mode, "fixture");
        assert!(snap.scan_p95_ms >= 94);
        assert!(snap.scan_p99_ms >= 98);
        assert!(snap.va_p95_ms >= 48);
        assert_eq!(snap.va2_p95_ms, 0);
        assert!(snap.sample_size >= 140);
    }
}
