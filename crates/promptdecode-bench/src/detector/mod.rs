//! The detector seam: a narrow, text-only trait that promptdecode engines
//! plug into later.

pub mod unicode_classes;

pub use unicode_classes::UnicodeClasses;

/// A prompt-smuggling detector.
///
/// Implementations see exactly one string and return one
/// [`Verdict`]. Nothing else crosses this seam: no file system, no clock, no
/// environment, no configuration. Keeping it text-only is what makes results
/// from different detectors comparable and every score auditable with
/// `--explain`.
///
/// # Determinism contract
///
/// [`Detector::score`] must be a **pure function of `text`**: the same input
/// always produces the same score and the same evidence, with no side
/// effects, no randomness, no wall-clock dependence, and no dependence on
/// prior calls. The whole benchmark's reproducibility — byte-identical
/// `results.json` from a committed corpus, asserted by `--check` in CI —
/// rests on this.
pub trait Detector {
    /// Stable machine identifier, e.g. `"unicode-classes"`.
    fn id(&self) -> &str;

    /// Human-readable name for reports, e.g. `"Unicode character classes"`.
    fn name(&self) -> &str;

    /// Version of the detector itself. Bump this whenever scoring behaviour
    /// changes: results are only comparable within a version.
    fn version(&self) -> &str;

    /// Score a single case text. Higher means more evidence of smuggling;
    /// `0.0` means no evidence at all. Must be deterministic and
    /// side-effect free — see the determinism contract above.
    fn score(&self, text: &str) -> Verdict;
}

/// The outcome of scoring one text.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    /// Non-negative evidence score; `0.0` means no evidence of smuggling.
    pub score: f64,
    /// Per-signal breakdown, in the detector's declared signal order.
    /// Signals that fired zero times are omitted.
    pub evidence: Vec<Evidence>,
}

/// One signal's contribution to a [`Verdict`].
#[derive(Debug, Clone, PartialEq)]
pub struct Evidence {
    /// Stable signal identifier, e.g. `"tag-block"`.
    pub class: String,
    /// How many occurrences the signal observed (before capping).
    pub count: usize,
    /// What the occurrence count added to the score after the per-class cap.
    pub contribution: f64,
    /// Human-readable explanation naming what was seen — the audit trail a
    /// reader checks by hand with `--explain`.
    pub note: String,
}
