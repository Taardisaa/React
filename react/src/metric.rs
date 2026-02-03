use crate::dataset::{State, TestResult};

/// Returns (tp, tn, fp, fn, unknown)
pub fn tp_tn_fp_fn(results: &[TestResult]) -> (usize, usize, usize, usize, usize) {
    let mut tp = 0;
    let mut tn = 0;
    let mut fp = 0;
    let mut fn_ = 0;
    let mut unknown = 0;
    for r in results {
        match (r.result, r.test.ground_truth) {
            (State::Vuln, State::Vuln) => tp += 1,
            (State::Patch, State::Patch) => tn += 1,
            (State::Vuln, State::Patch) => fp += 1,
            (State::Patch, State::Vuln) => fn_ += 1,
            (State::Unknown, _) => unknown += 1,
            // Unknown ground truth should not happen, but handle gracefully
            (_, State::Unknown) => unknown += 1,
        }
    }
    (tp, tn, fp, fn_, unknown)
}

/// Returns (precision, recall, f1, coverage)
/// Coverage = proportion of cases that were actually analyzed (not Unknown)
pub fn precision_recall_f1(results: &[TestResult]) -> (f64, f64, f64, f64) {
    let (tp, _tn, fp, fn_, unknown) = tp_tn_fp_fn(results);
    let total = results.len();
    let analyzed = total - unknown;

    let coverage = if total > 0 {
        analyzed as f64 / total as f64
    } else {
        0.0
    };

    let p = if tp + fp > 0 {
        tp as f64 / (tp + fp) as f64
    } else {
        0.0
    };
    let r = if tp + fn_ > 0 {
        tp as f64 / (tp + fn_) as f64
    } else {
        0.0
    };
    let f1 = if p + r > 0.0 {
        2.0 * p * r / (p + r)
    } else {
        0.0
    };
    (p, r, f1, coverage)
}
