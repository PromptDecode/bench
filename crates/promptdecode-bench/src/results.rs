//! The `results.json` model and its deterministic serialisation.
//!
//! # Reproducibility contract (deliberate)
//!
//! `results.json` contains **no wall-clock timestamp, no hostname, and no
//! absolute paths** — nowhere, in any field. The file must be byte-for-byte
//! reproducible from the committed corpus alone, so CI can assert
//! `git diff --exit-code results.json` after re-running the bench. If you are
//! about to add a field derived from the machine or the moment of the run,
//! you are about to break that contract.
//!
//! Field names and nesting are a contract with the rendering site: they must
//! not be renamed without a `schema_version` bump. serde emits struct fields
//! in declaration order, which is exactly the documented order.
//!
//! `threshold` of `null` in serialised output means "the detector must fire
//! on nothing at all to meet the target FPR" (an infinite threshold — JSON
//! has no infinity literal).

use serde::{Deserialize, Serialize};

use crate::corpus::{Corpus, Label};
use crate::detector::Detector;
use crate::error::{BenchError, Result};
use crate::metrics::{all_operating_points, resolution, OperatingPoint, Resolution, ScoredCase};

/// The results document's schema version. Bump only for breaking changes to
/// the shape below.
pub const RESULTS_SCHEMA_VERSION: u32 = 1;

/// The corpus name recorded in every results file.
pub const CORPUS_NAME: &str = "promptdecode-bench";

/// The caveat that travels with the recall figure, serialised into every
/// `results.json` immediately after `schema_version`. This is a fixed
/// constant, deliberately: the rendering site draws `results.json` directly,
/// and its ethos is to never publish a bare effectiveness percentage — so the
/// caveat is part of the artefact itself and cannot be separated from the
/// number it qualifies.
pub const INTERPRETATION: &str = "This detector separates this corpus completely. That is a fact about a corpus and a detector written in the same repository, not evidence that the detector generalises. Until the corpus contains cases this detector fails, the recall figure measures the difficulty of the corpus, not the reach of the detector.";

/// The complete results document.
#[derive(Debug, Clone, Serialize)]
pub struct ResultsReport {
    /// Always [`RESULTS_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Always [`INTERPRETATION`]; never computed, never conditional.
    pub interpretation: String,
    /// What was measured.
    pub corpus: CorpusSection,
    /// What did the measuring.
    pub detector: DetectorSection,
    /// How fine a false-positive rate this corpus can resolve.
    pub resolution: Resolution,
    /// One entry per target FPR, ascending.
    pub operating_points: Vec<OperatingPoint>,
}

/// The corpus half of the results document.
#[derive(Debug, Clone, Serialize)]
pub struct CorpusSection {
    /// Always [`CORPUS_NAME`].
    pub name: String,
    /// `"sha256:<hex>"` over the raw corpus bytes (see `Corpus::digest`).
    pub digest: String,
    /// Case totals.
    pub cases: CaseTotals,
    /// Families sorted by name.
    pub families: Vec<FamilySummary>,
    /// Sources sorted by id, with per-source case counts.
    pub sources: Vec<SourceSummary>,
}

/// Attack/benign/total case counts.
#[derive(Debug, Clone, Serialize)]
pub struct CaseTotals {
    /// All cases.
    pub total: usize,
    /// Cases labelled attack.
    pub attack: usize,
    /// Cases labelled benign.
    pub benign: usize,
}

/// One family's entry in the corpus section.
#[derive(Debug, Clone, Serialize)]
pub struct FamilySummary {
    /// Family name.
    pub family: String,
    /// The family's label.
    pub label: Label,
    /// The family's description, verbatim from the family file.
    pub description: String,
    /// Number of cases in the family.
    pub cases: usize,
}

/// One source's entry in the corpus section.
#[derive(Debug, Clone, Serialize)]
pub struct SourceSummary {
    /// Source id.
    pub id: String,
    /// Human-readable provenance description.
    pub name: String,
    /// Where the source lives, if registered.
    pub url: Option<String>,
    /// SPDX licence identifier.
    pub licence: String,
    /// URL of the licence text.
    pub licence_url: String,
    /// How many cases cite this source.
    pub cases: usize,
}

/// The detector half of the results document.
#[derive(Debug, Clone, Serialize)]
pub struct DetectorSection {
    /// Stable detector id.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Detector version.
    pub version: String,
}

/// Builds the full results document from a loaded corpus, a detector, and
/// the corpus's scored cases.
pub fn build_report(
    corpus: &Corpus,
    detector: &dyn Detector,
    scored: &[ScoredCase],
) -> ResultsReport {
    let attack = scored.iter().filter(|c| c.label == Label::Attack).count();
    let benign = scored.len() - attack;

    let mut families: Vec<FamilySummary> = corpus
        .families
        .iter()
        .map(|f| FamilySummary {
            family: f.family.clone(),
            label: f.label,
            description: f.description.clone(),
            cases: f.cases.len(),
        })
        .collect();
    families.sort_by(|a, b| a.family.cmp(&b.family));

    let mut sources: Vec<SourceSummary> = corpus
        .sources
        .iter()
        .map(|s| SourceSummary {
            cases: scored.iter().filter(|c| c.source_id == s.id).count(),
            id: s.id.clone(),
            name: s.name.clone(),
            url: s.url.clone(),
            licence: s.licence.clone(),
            licence_url: s.licence_url.clone(),
        })
        .collect();
    sources.sort_by(|a, b| a.id.cmp(&b.id));

    ResultsReport {
        schema_version: RESULTS_SCHEMA_VERSION,
        interpretation: INTERPRETATION.to_string(),
        corpus: CorpusSection {
            name: CORPUS_NAME.to_string(),
            digest: corpus.digest(),
            cases: CaseTotals {
                total: scored.len(),
                attack,
                benign,
            },
            families,
            sources,
        },
        detector: DetectorSection {
            id: detector.id().to_string(),
            name: detector.name().to_string(),
            version: detector.version().to_string(),
        },
        resolution: resolution(scored),
        operating_points: all_operating_points(scored),
    }
}

/// Renders the report as pretty JSON with a 2-space indent and a trailing
/// newline — the exact bytes written to `results.json` and compared by
/// `--check`.
pub fn render(report: &ResultsReport) -> Result<String> {
    let mut json = serde_json::to_string_pretty(report).map_err(|e| BenchError::Serialisation {
        message: format!("failed to serialise results: {e}"),
    })?;
    json.push('\n');
    Ok(json)
}

/// One operating point's recall floor.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineOperatingPoint {
    /// Target FPR this floor applies to; matches an operating point.
    pub target_fpr: f64,
    /// Recall must be `>= min_recall` or the bench fails.
    pub min_recall: f64,
}

/// The `baseline.json` model: recall floors the benchmark must not drop
/// below, raised deliberately in the same commit as the change that earns
/// them.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    /// Currently 1.
    pub schema_version: u32,
    /// Why the floors are where they are.
    pub note: String,
    /// The detector id the floors apply to; a different detector is an error.
    pub detector: String,
    /// One floor per target FPR.
    pub operating_points: Vec<BaselineOperatingPoint>,
}

/// Parses and validates `baseline.json` content.
pub fn parse_baseline(text: &str) -> Result<Baseline> {
    let baseline: Baseline = serde_json::from_str(text).map_err(|e| BenchError::ParseJson {
        path: std::path::PathBuf::from("baseline.json"),
        source: e,
    })?;
    if baseline.schema_version != RESULTS_SCHEMA_VERSION {
        return Err(BenchError::Validation {
            message: format!(
                "baseline.json schema_version {} is not supported (expected {})",
                baseline.schema_version, RESULTS_SCHEMA_VERSION
            ),
        });
    }
    if baseline.detector.trim().is_empty() {
        return Err(BenchError::Validation {
            message: "baseline.json has an empty detector id".to_string(),
        });
    }
    if baseline.operating_points.is_empty() {
        return Err(BenchError::Validation {
            message: "baseline.json has no operating_points: an empty baseline would silently disable the recall-floor regression gate".to_string(),
        });
    }
    for op in &baseline.operating_points {
        if !(0.0..=1.0).contains(&op.min_recall) {
            return Err(BenchError::Validation {
                message: format!(
                    "baseline operating point target_fpr={} has min_recall {} outside [0, 1]",
                    op.target_fpr, op.min_recall
                ),
            });
        }
    }
    Ok(baseline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::Label;
    use crate::metrics::ScoredCase;

    fn scored() -> Vec<ScoredCase> {
        vec![
            ScoredCase {
                id: "a-01".into(),
                family: "fam-a".into(),
                label: Label::Attack,
                source_id: "s".into(),
                score: 12.0,
            },
            ScoredCase {
                id: "a-02".into(),
                family: "fam-a".into(),
                label: Label::Attack,
                source_id: "s".into(),
                score: 0.0,
            },
            ScoredCase {
                id: "b-01".into(),
                family: "fam-b".into(),
                label: Label::Benign,
                source_id: "s".into(),
                score: 0.0,
            },
            ScoredCase {
                id: "b-02".into(),
                family: "fam-b".into(),
                label: Label::Benign,
                source_id: "s".into(),
                score: 3.0,
            },
        ]
    }

    #[test]
    fn renders_field_order_and_trailing_newline() {
        let report = fixture_report(scored());
        let json = render(&report).unwrap();
        assert!(json.ends_with("}\n"));
        // Field order: schema_version first, interpretation immediately after
        // it, operating_points last; counts in contract order inside every
        // operating point.
        assert!(json.contains("\"schema_version\": 1"));
        let schema_pos = json.find("\"schema_version\"").unwrap();
        let interpretation_pos = json.find("\"interpretation\"").unwrap();
        let corpus_pos = json.find("\"corpus\"").unwrap();
        let detector_pos = json.find("\"detector\"").unwrap();
        let resolution_pos = json.find("\"resolution\"").unwrap();
        let ops_pos = json.find("\"operating_points\"").unwrap();
        assert!(schema_pos < interpretation_pos && interpretation_pos < corpus_pos);
        assert!(corpus_pos < detector_pos);
        assert!(detector_pos < resolution_pos && resolution_pos < ops_pos);
        let counts_pos = json.find("\"counts\"").unwrap();
        let tp = json.find("\"true_positives\"").unwrap();
        let fneg = json.find("\"false_negatives\"").unwrap();
        let fp = json.find("\"false_positives\"").unwrap();
        let tn = json.find("\"true_negatives\"").unwrap();
        assert!(counts_pos < tp && tp < fneg && fneg < fp && fp < tn);
    }

    #[test]
    fn rendered_output_carries_the_interpretation_verbatim() {
        let report = fixture_report(scored());
        let json = render(&report).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let rendered = value["interpretation"].as_str().unwrap_or_default();
        assert!(!rendered.is_empty(), "interpretation must be non-empty");
        assert_eq!(rendered, INTERPRETATION);
    }

    #[test]
    fn baseline_parses_and_validates() {
        let baseline = parse_baseline(
            r#"{
  "schema_version": 1,
  "note": "floors",
  "detector": "unicode-classes",
  "operating_points": [ { "target_fpr": 0.0, "min_recall": 0.5 } ]
}"#,
        )
        .unwrap();
        assert_eq!(baseline.operating_points.len(), 1);
        assert!(parse_baseline(
            r#"{ "schema_version": 2, "note": "n", "detector": "d", "operating_points": [] }"#
        )
        .is_err());
        assert!(parse_baseline(
            r#"{ "schema_version": 1, "note": "n", "detector": "d", "operating_points": [ { "target_fpr": 0.0, "min_recall": 1.5 } ] }"#
        )
        .is_err());
        assert!(parse_baseline(
            r#"{ "schema_version": 1, "note": "n", "detector": "d", "surprise": true, "operating_points": [] }"#
        )
        .is_err());
    }

    #[test]
    fn baseline_with_no_operating_points_is_a_load_error() {
        // An empty floor list would make the regression gate loop over
        // nothing and pass — a vacuous baseline must not load.
        let err = parse_baseline(
            r#"{ "schema_version": 1, "note": "n", "detector": "d", "operating_points": [] }"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("no operating_points"), "{err}");
    }

    // A stand-in so tests can build a report without a real corpus on disk;
    // build_report is exercised against the real corpus by the integration
    // tests.
    fn fixture_report(scored_cases: Vec<ScoredCase>) -> ResultsReport {
        let ops = crate::metrics::all_operating_points(&scored_cases);
        ResultsReport {
            schema_version: RESULTS_SCHEMA_VERSION,
            interpretation: INTERPRETATION.to_string(),
            corpus: CorpusSection {
                name: CORPUS_NAME.to_string(),
                digest: "sha256:test".to_string(),
                cases: CaseTotals {
                    total: 4,
                    attack: 2,
                    benign: 2,
                },
                families: vec![FamilySummary {
                    family: "fam-a".to_string(),
                    label: Label::Attack,
                    description: "d".to_string(),
                    cases: 2,
                }],
                sources: vec![],
            },
            detector: DetectorSection {
                id: "unicode-classes".to_string(),
                name: "n".to_string(),
                version: "0.1.0".to_string(),
            },
            resolution: Resolution {
                benign_cases: 2,
                finest_nonzero_fpr: 0.5,
            },
            operating_points: ops,
        }
    }
}
