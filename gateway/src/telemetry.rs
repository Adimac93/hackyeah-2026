//! In-process performance telemetry (§6): per-stage latency percentiles,
//! verdict and error counts, detector availability and the async semantic
//! queue depth, rendered in the Prometheus text format.
//!
//! The audit log already holds per-event latency for historical reporting;
//! this is the live view a scraper polls, kept in memory so a scrape never
//! touches the database.

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, Ordering};

/// Samples kept per stage. Percentiles are over this sliding window.
const WINDOW: usize = 2_048;

#[derive(Default)]
pub struct Telemetry {
    stages: Mutex<BTreeMap<&'static str, VecDeque<u64>>>,
    counters: Mutex<BTreeMap<String, u64>>,
    /// Async semantic evaluations spawned but not finished.
    pub queue_depth: AtomicI64,
}

impl Telemetry {
    /// Record one stage duration in microseconds. Stages: `deterministic`,
    /// `semantic`, `upstream`, `mcp_upstream`, `total`.
    pub fn observe(&self, stage: &'static str, micros: u64) {
        if let Ok(mut stages) = self.stages.lock() {
            let samples = stages.entry(stage).or_default();
            if samples.len() == WINDOW {
                samples.pop_front();
            }
            samples.push_back(micros);
        }
    }

    /// Increment a labelled counter, e.g. `verdict{hook="prompt_in",verdict="block"}`.
    pub fn count(&self, series: String) {
        if let Ok(mut counters) = self.counters.lock() {
            *counters.entry(series).or_default() += 1;
        }
    }

    pub fn verdict(&self, hook: &str, verdict: &str) {
        self.count(format!(
            "gateway_verdicts_total{{hook=\"{hook}\",verdict=\"{verdict}\"}}"
        ));
    }

    /// A call to a model or detector, successful or not: availability.
    pub fn dependency(&self, name: &str, ok: bool) {
        let outcome = if ok { "ok" } else { "error" };
        self.count(format!(
            "gateway_dependency_calls_total{{dependency=\"{name}\",outcome=\"{outcome}\"}}"
        ));
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("# TYPE gateway_stage_latency_us summary\n");
        if let Ok(stages) = self.stages.lock() {
            for (stage, samples) in stages.iter() {
                let mut sorted: Vec<u64> = samples.iter().copied().collect();
                sorted.sort_unstable();
                for (label, q) in [("0.5", 0.5), ("0.95", 0.95), ("0.99", 0.99)] {
                    let _ = writeln!(
                        out,
                        "gateway_stage_latency_us{{stage=\"{stage}\",quantile=\"{label}\"}} {}",
                        percentile(&sorted, q)
                    );
                }
                let _ = writeln!(
                    out,
                    "gateway_stage_latency_us_count{{stage=\"{stage}\"}} {}",
                    sorted.len()
                );
            }
        }
        out.push_str("# TYPE gateway_verdicts_total counter\n");
        out.push_str("# TYPE gateway_dependency_calls_total counter\n");
        if let Ok(counters) = self.counters.lock() {
            for (series, value) in counters.iter() {
                let _ = writeln!(out, "{series} {value}");
            }
        }
        out.push_str("# TYPE gateway_semantic_queue_depth gauge\n");
        let _ = writeln!(
            out,
            "gateway_semantic_queue_depth {}",
            self.queue_depth.load(Ordering::Relaxed)
        );
        out
    }
}

/// Nearest-rank percentile of an ascending slice; 0 when empty.
pub fn percentile(sorted: &[u64], q: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "an index into a window of at most 2048 samples"
    )]
    let rank = ((q * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_use_nearest_rank() {
        let samples: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&samples, 0.5), 50);
        assert_eq!(percentile(&samples, 0.95), 95);
        assert_eq!(percentile(&samples, 0.99), 99);
        assert_eq!(percentile(&[], 0.5), 0);
        assert_eq!(percentile(&[7], 0.99), 7);
    }

    #[test]
    fn render_reports_stages_counters_and_queue_depth() {
        let telemetry = Telemetry::default();
        telemetry.observe("deterministic", 120);
        telemetry.verdict("prompt_in", "block");
        telemetry.queue_depth.store(3, Ordering::Relaxed);
        let text = telemetry.render();
        assert!(text.contains(r#"gateway_stage_latency_us{stage="deterministic",quantile="0.5"} 120"#));
        assert!(text.contains(r#"gateway_verdicts_total{hook="prompt_in",verdict="block"} 1"#));
        assert!(text.contains("gateway_semantic_queue_depth 3"));
    }
}
