//! Threshold sweeps and operating points: recall at a stated false-positive
//! rate.
//!
//! # Threshold selection is well defined
//!
//! Candidate thresholds are the distinct observed scores plus
//! `f64::INFINITY`; a detector *fires* on a case when `score >= threshold`.
//! For a target FPR we pick the **smallest** candidate threshold whose
//! false-positive rate on benign cases is `<= target_fpr`. There is always
//! at least one such threshold — `INFINITY` fires on nothing and so has FPR
//! 0 — and because the candidate set is finite and sorted, the smallest
//! qualifying threshold is unique. Choosing the smallest (rather than any
//! qualifying) threshold maximises recall at that FPR, so the number
//! reported for a detector is the best it can do, not an artefact of where
//! someone happened to put a dial.
//!
//! All reported rates are rounded to 6 decimal places so serialised output
//! is byte-stable across platforms. Comparisons against `target_fpr` use
//! unrounded values; only the *reported* numbers are rounded.

use crate::corpus::{Corpus, Label};
use crate::detector::Detector;

/// The target false-positive rates every detector is evaluated against.
pub const TARGET_FPRS: [f64; 3] = [0.0, 0.01, 0.05];

/// Rounds to 6 decimal places — the precision every reported rate carries.
pub fn round6(x: f64) -> f64 {
    (x * 1_000_000.0).round() / 1_000_000.0
}

/// One corpus case with its score, in the order it was scored.
#[derive(Debug, Clone)]
pub struct ScoredCase {
    /// Case id.
    pub id: String,
    /// Family the case came from.
    pub family: String,
    /// Attack or benign.
    pub label: Label,
    /// The case's registered source id.
    pub source_id: String,
    /// The detector's score for this case's text.
    pub score: f64,
}

/// Scores every case in the corpus, in the corpus's deterministic (id-sorted)
/// order, with the given detector.
pub fn score_corpus(corpus: &Corpus, detector: &dyn Detector) -> Vec<ScoredCase> {
    corpus
        .cases
        .iter()
        .map(|case| ScoredCase {
            id: case.id.clone(),
            family: case.family.clone(),
            label: case.label,
            source_id: case.source_id.clone(),
            score: detector.score(&case.text).score,
        })
        .collect()
}

/// Confusion counts at one threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Counts {
    /// Attack cases that fired.
    pub true_positives: usize,
    /// Attack cases that did not fire.
    pub false_negatives: usize,
    /// Benign cases that fired.
    pub false_positives: usize,
    /// Benign cases that did not fire.
    pub true_negatives: usize,
}

/// Per-family outcome at one operating point.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FamilyOutcome {
    /// Family name.
    pub family: String,
    /// The family's label.
    pub label: Label,
    /// Cases in the family.
    pub cases: usize,
    /// Cases that fired at the threshold.
    pub detected: usize,
    /// `detected / cases`, rounded to 6 dp.
    pub rate: f64,
}

/// One threshold decision: the detector's operating point for one target FPR.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OperatingPoint {
    /// The target false-positive rate asked for.
    pub target_fpr: f64,
    /// The smallest threshold meeting the target; fires when
    /// `score >= threshold`. `INFINITY` means "fire on nothing".
    pub threshold: f64,
    /// Recall at the threshold, rounded to 6 dp.
    pub recall: f64,
    /// Achieved false-positive rate at the threshold, rounded to 6 dp.
    pub false_positive_rate: f64,
    /// Confusion counts at the threshold.
    pub counts: Counts,
    /// Sorted ids of attack cases that did not fire.
    pub missed_attack_cases: Vec<String>,
    /// Sorted ids of benign cases that did fire.
    pub false_positive_cases: Vec<String>,
    /// Per-family detection outcomes, sorted by family name.
    pub by_family: Vec<FamilyOutcome>,
}

/// Computes the operating point for `target_fpr` from scored cases.
///
/// Cases in `scored` may be in any order; outputs are sorted. A detector
/// fires when `score >= threshold`. Candidate thresholds are the distinct
/// observed scores plus `INFINITY`; the smallest candidate whose benign FPR
/// is `<= target_fpr` wins (see the module docs for why this is well
/// defined). When the corpus contains no benign cases, the FPR of every
/// threshold is 0.0 by convention (there is nothing to be false positive
/// about); with no attack cases, recall is 0.0.
pub fn operating_point(target_fpr: f64, scored: &[ScoredCase]) -> OperatingPoint {
    let mut candidates: Vec<f64> = scored.iter().map(|c| c.score).collect();
    candidates.push(f64::INFINITY);
    candidates.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    candidates.dedup();

    let benign: Vec<&ScoredCase> = scored.iter().filter(|c| c.label == Label::Benign).collect();
    let attack: Vec<&ScoredCase> = scored.iter().filter(|c| c.label == Label::Attack).collect();

    let fpr_at = |threshold: f64| -> f64 {
        if benign.is_empty() {
            return 0.0;
        }
        let fp = benign.iter().filter(|c| c.score >= threshold).count();
        fp as f64 / benign.len() as f64
    };

    let mut threshold = f64::INFINITY;
    for &candidate in &candidates {
        if fpr_at(candidate) <= target_fpr {
            threshold = candidate;
            break;
        }
    }

    let true_positives = attack.iter().filter(|c| c.score >= threshold).count();
    let false_negatives = attack.len() - true_positives;
    let false_positives = benign.iter().filter(|c| c.score >= threshold).count();
    let true_negatives = benign.len() - false_positives;

    let recall = if attack.is_empty() {
        0.0
    } else {
        true_positives as f64 / attack.len() as f64
    };

    let mut missed_attack_cases: Vec<String> = attack
        .iter()
        .filter(|c| c.score < threshold)
        .map(|c| c.id.clone())
        .collect();
    missed_attack_cases.sort();

    let mut false_positive_cases: Vec<String> = benign
        .iter()
        .filter(|c| c.score >= threshold)
        .map(|c| c.id.clone())
        .collect();
    false_positive_cases.sort();

    let mut by_family: Vec<FamilyOutcome> = Vec::new();
    for case in scored {
        if let Some(slot) = by_family.iter_mut().find(|f| f.family == case.family) {
            slot.cases += 1;
            if case.score >= threshold {
                slot.detected += 1;
            }
        } else {
            by_family.push(FamilyOutcome {
                family: case.family.clone(),
                label: case.label,
                cases: 1,
                detected: usize::from(case.score >= threshold),
                rate: 0.0,
            });
        }
    }
    by_family.sort_by(|a, b| a.family.cmp(&b.family));
    for family in &mut by_family {
        family.rate = if family.cases == 0 {
            0.0
        } else {
            round6(family.detected as f64 / family.cases as f64)
        };
    }

    OperatingPoint {
        target_fpr,
        threshold,
        recall: round6(recall),
        false_positive_rate: round6(fpr_at(threshold)),
        counts: Counts {
            true_positives,
            false_negatives,
            false_positives,
            true_negatives,
        },
        missed_attack_cases,
        false_positive_cases,
        by_family,
    }
}

/// Computes operating points for [`TARGET_FPRS`], in ascending target order.
pub fn all_operating_points(scored: &[ScoredCase]) -> Vec<OperatingPoint> {
    TARGET_FPRS
        .map(|target| operating_point(target, scored))
        .to_vec()
}

/// The honesty block: how fine a false-positive rate this corpus can even
/// express. With `n` benign cases the finest non-zero FPR is `1/n`; a target
/// below that (such as 0.01 on a small corpus) is visibly unresolvable
/// rather than silently treated as 0.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Resolution {
    /// Number of benign cases in the corpus.
    pub benign_cases: usize,
    /// `1 / benign_cases`, rounded to 6 dp; 0.0 when there are none.
    pub finest_nonzero_fpr: f64,
}

/// Computes the corpus's resolution block from scored cases.
pub fn resolution(scored: &[ScoredCase]) -> Resolution {
    let benign = scored.iter().filter(|c| c.label == Label::Benign).count();
    Resolution {
        benign_cases: benign,
        finest_nonzero_fpr: if benign == 0 {
            0.0
        } else {
            round6(1.0 / benign as f64)
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scored(scores: &[(&str, Label, f64)]) -> Vec<ScoredCase> {
        scores
            .iter()
            .map(|&(id, label, score)| ScoredCase {
                id: id.to_string(),
                family: "f".to_string(),
                label,
                source_id: "s".to_string(),
                score,
            })
            .collect()
    }

    #[test]
    fn selects_smallest_threshold_meeting_target() {
        let cases = scored(&[
            ("b1", Label::Benign, 0.0),
            ("a1", Label::Attack, 1.0),
            ("a2", Label::Attack, 2.0),
            ("b2", Label::Benign, 2.0),
            ("a3", Label::Attack, 3.0),
        ]);
        // Hand-computed candidates: 0.0, 1.0, 2.0, 3.0, INF.
        // target 0.0: t=0 fpr 1.0; t=1 fpr 0.5; t=2 fpr 0.5; t=3 fpr 0 <= 0. Threshold 3.
        let op = operating_point(0.0, &cases);
        assert_eq!(op.threshold, 3.0);
        assert_eq!(op.recall, round6(1.0 / 3.0));
        assert_eq!(op.false_positive_rate, 0.0);
        assert_eq!(op.counts.true_positives, 1);
        assert_eq!(op.counts.false_negatives, 2);
        assert_eq!(op.counts.false_positives, 0);
        assert_eq!(op.counts.true_negatives, 2);
        assert_eq!(op.missed_attack_cases, vec!["a1", "a2"]);
        assert!(op.false_positive_cases.is_empty());

        // target 0.5: t=0 fpr 1.0; t=1 fpr 0.5 <= 0.5. Threshold 1, full recall.
        let op = operating_point(0.5, &cases);
        assert_eq!(op.threshold, 1.0);
        assert_eq!(op.recall, 1.0);
        assert_eq!(op.false_positive_rate, 0.5);
        assert_eq!(op.false_positive_cases, vec!["b2"]);

        // target 1.0: even t=0 qualifies (fpr 1.0 <= 1.0).
        let op = operating_point(1.0, &cases);
        assert_eq!(op.threshold, 0.0);
        assert_eq!(op.recall, 1.0);
    }

    #[test]
    fn ties_at_threshold_fire_together() {
        // Attack and benign share the score 2.0: a threshold of 2.0 makes
        // both fire, so target 0.0 must skip past it.
        let cases = scored(&[
            ("a1", Label::Attack, 2.0),
            ("b1", Label::Benign, 2.0),
            ("a2", Label::Attack, 5.0),
        ]);
        let op = operating_point(0.0, &cases);
        assert_eq!(op.threshold, 5.0, "t=2.0 has fpr 1.0, so 5.0 must win");
        assert_eq!(op.counts.true_positives, 1);
        // b1 scores 2.0, below the chosen threshold, so it does not fire.
        assert!(op.false_positive_cases.is_empty());
        // At target 1.0 the tied threshold is chosen and both sides fire.
        let op = operating_point(1.0, &cases);
        assert_eq!(op.threshold, 2.0);
        assert_eq!(op.counts.true_positives, 2);
        assert_eq!(op.counts.false_positives, 1);
    }

    #[test]
    fn all_zero_scores() {
        let cases = scored(&[
            ("a1", Label::Attack, 0.0),
            ("a2", Label::Attack, 0.0),
            ("b1", Label::Benign, 0.0),
        ]);
        // target 0.0: t=0 fires on everything (fpr 1.0), so INF: recall 0.
        let op = operating_point(0.0, &cases);
        assert_eq!(op.threshold, f64::INFINITY);
        assert_eq!(op.recall, 0.0);
        assert_eq!(op.false_positive_rate, 0.0);
        assert_eq!(op.counts.true_positives, 0);
        assert_eq!(op.counts.false_negatives, 2);
        assert_eq!(op.counts.true_negatives, 1);
        assert_eq!(op.missed_attack_cases, vec!["a1", "a2"]);
        // target 1.0: t=0 qualifies.
        let op = operating_point(1.0, &cases);
        assert_eq!(op.threshold, 0.0);
        assert_eq!(op.recall, 1.0);
    }

    #[test]
    fn unachievable_target_falls_back_to_infinity() {
        let cases = scored(&[
            ("b1", Label::Benign, 0.0),
            ("b2", Label::Benign, 1.0),
            ("a1", Label::Attack, 0.5),
        ]);
        // Any finite threshold fires on at least one benign case (fpr >= 0.5).
        let op = operating_point(0.25, &cases);
        assert_eq!(op.threshold, f64::INFINITY);
        assert_eq!(op.recall, 0.0);
        assert_eq!(op.missed_attack_cases, vec!["a1"]);
        assert_eq!(op.false_positive_cases, Vec::<String>::new());
    }

    #[test]
    fn target_zero_with_clean_separation() {
        let cases = scored(&[
            ("b1", Label::Benign, 0.0),
            ("b2", Label::Benign, 0.5),
            ("a1", Label::Attack, 1.0),
        ]);
        let op = operating_point(0.0, &cases);
        assert_eq!(op.threshold, 1.0);
        assert_eq!(op.recall, 1.0);
        assert_eq!(
            op.counts,
            Counts {
                true_positives: 1,
                false_negatives: 0,
                false_positives: 0,
                true_negatives: 2
            }
        );
    }

    #[test]
    fn empty_corpus_is_handled() {
        let op = operating_point(0.0, &[]);
        assert_eq!(op.threshold, f64::INFINITY);
        assert_eq!(op.recall, 0.0);
        assert_eq!(op.false_positive_rate, 0.0);
        assert_eq!(
            op.counts,
            Counts {
                true_positives: 0,
                false_negatives: 0,
                false_positives: 0,
                true_negatives: 0
            }
        );
    }

    #[test]
    fn rounding_is_six_decimals() {
        assert_eq!(round6(1.0 / 3.0), 0.333333);
        assert_eq!(round6(2.0 / 3.0), 0.666667);
        assert_eq!(round6(0.0), 0.0);
        assert_eq!(round6(1.0), 1.0);
        let cases = scored(&[("b1", Label::Benign, 0.0), ("a1", Label::Attack, 1.0)]);
        // 1 benign case: fpr is always 0 or 1. With target 0.0, threshold 1.0.
        let op = operating_point(0.0, &cases);
        assert_eq!(op.false_positive_rate, 0.0);
        let resolution = resolution(&cases);
        assert_eq!(resolution.benign_cases, 1);
        assert_eq!(resolution.finest_nonzero_fpr, 1.0);
    }

    #[test]
    fn resolution_reports_corpus_finest_fpr() {
        let mut cases = scored(&[("a1", Label::Attack, 1.0)]);
        for i in 0..7 {
            cases.push(ScoredCase {
                id: format!("b{i}"),
                family: "f".to_string(),
                label: Label::Benign,
                source_id: "s".to_string(),
                score: 0.0,
            });
        }
        let r = resolution(&cases);
        assert_eq!(r.benign_cases, 7);
        assert_eq!(r.finest_nonzero_fpr, round6(1.0 / 7.0));
        assert_eq!(r.finest_nonzero_fpr, 0.142857);
    }

    #[test]
    fn by_family_counts_and_rates() {
        let cases = scored(&[
            ("a1", Label::Attack, 2.0),
            ("a2", Label::Attack, 0.0),
            ("b1", Label::Benign, 0.0),
        ]);
        // Threshold 2.0 for target 0.0 (only candidate with fpr 0).
        let op = operating_point(0.0, &cases);
        let f = &op.by_family[0];
        assert_eq!(f.cases, 3);
        assert_eq!(f.detected, 1);
        assert_eq!(f.rate, 0.333333);
    }
}
