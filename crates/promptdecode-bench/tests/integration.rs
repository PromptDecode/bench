//! Integration tests against the real committed corpus and results file.
//!
//! These deliberately reach outside the crate (via `CARGO_MANIFEST_DIR`) into
//! the repository root, because the point is to test what is actually
//! committed.

use std::path::PathBuf;

use promptdecode_bench::detector::UnicodeClasses;
use promptdecode_bench::metrics::{resolution, score_corpus};
use promptdecode_bench::results::{build_report, render};
use promptdecode_bench::{Corpus, Detector};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn corpus_dir() -> PathBuf {
    repo_root().join("corpus")
}

fn results_path() -> PathBuf {
    repo_root().join("results.json")
}

/// The real committed corpus must validate with no errors.
#[test]
fn committed_corpus_loads_and_validates() {
    let corpus = Corpus::load(&corpus_dir())
        .unwrap_or_else(|e| panic!("the committed corpus must validate, but: {e}"));
    assert!(
        !corpus.cases.is_empty(),
        "the committed corpus should contain at least one case"
    );
    // Every case resolves to a real source with a licence.
    for case in &corpus.cases {
        let source = corpus
            .sources
            .iter()
            .find(|s| s.id == case.source_id)
            .unwrap_or_else(|| panic!("case {} has an unresolvable source", case.id));
        assert!(!source.licence.is_empty());
        assert!(!source.licence_url.is_empty());
    }
}

/// Recomputing the results from the committed corpus must reproduce the
/// committed results.json byte-for-byte. Skips gracefully with a clear
/// message if results.json does not exist yet (e.g. on the very first run).
#[test]
fn recomputed_results_match_committed_results_json() {
    let path = results_path();
    if !path.exists() {
        eprintln!(
            "skipping: {} does not exist yet; run `cargo run -p promptdecode-bench` and commit the file it writes",
            path.display()
        );
        return;
    }
    let corpus = Corpus::load(&corpus_dir()).expect("committed corpus must validate");
    let detector = UnicodeClasses;
    let scored = score_corpus(&corpus, &detector);
    let rendered = render(&build_report(&corpus, &detector, &scored)).expect("results must render");
    let on_disk = std::fs::read_to_string(&path).expect("results.json must be readable");
    assert_eq!(
        rendered, on_disk,
        "results.json on disk differs from the freshly computed results; re-run the bench and commit the file"
    );
}

/// Sanity of the numbers: the detector under test should separate this
/// corpus at least at the loosest target FPR, and the resolution block must
/// agree with the benign count. Kept loose on purpose — it guards against a
/// harness wiring mistake, not against honest detector weakness.
#[test]
fn operating_points_are_wellformed() {
    let corpus = Corpus::load(&corpus_dir()).expect("committed corpus must validate");
    let detector = UnicodeClasses;
    let scored = score_corpus(&corpus, &detector);
    let report = build_report(&corpus, &detector, &scored);

    assert_eq!(report.corpus.cases.total, corpus.cases.len());
    assert_eq!(
        report.resolution.benign_cases,
        scored
            .iter()
            .filter(|c| c.label == promptdecode_bench::Label::Benign)
            .count()
    );
    let res = resolution(&scored);
    assert_eq!(res.benign_cases, report.resolution.benign_cases);

    let targets: Vec<f64> = report
        .operating_points
        .iter()
        .map(|op| op.target_fpr)
        .collect();
    assert_eq!(targets, vec![0.0, 0.01, 0.05]);
    for op in &report.operating_points {
        // Counts must add up.
        assert_eq!(
            op.counts.true_positives + op.counts.false_negatives,
            report.corpus.cases.attack
        );
        assert_eq!(
            op.counts.false_positives + op.counts.true_negatives,
            report.corpus.cases.benign
        );
        // Achieved FPR must honour the target.
        assert!(
            op.false_positive_rate <= op.target_fpr,
            "target_fpr={} achieved fpr={}",
            op.target_fpr,
            op.false_positive_rate
        );
    }
    // Detector self-report agrees with the trait; the version is a real
    // value, and the results record exactly what the detector reports — so a
    // version bump cannot strand a stale hard-coded literal here.
    assert_eq!(detector.id(), "unicode-classes");
    assert!(
        !detector.version().is_empty(),
        "detector version must be non-empty"
    );
    assert_eq!(
        report.detector.version,
        detector.version(),
        "results must record the detector's self-reported version"
    );
}
