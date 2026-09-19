//! # promptdecode-bench
//!
//! The open benchmark harness for prompt-smuggling detectors: it loads and
//! validates the corpus (`corpus/SCHEMA.md` is the normative specification),
//! scores it with a [`Detector`], and reports **recall at a stated
//! false-positive rate** in a byte-reproducible `results.json`.
//!
//! Module map:
//!
//! * [`corpus`] — schema types, family-file discovery, strict parsing, the
//!   raw-file lint (no literal invisible codepoints), validation.
//! * [`detector`] — the text-only [`Detector`] seam plus the
//!   [`UnicodeClasses`] reference detector with its thirteen signals.
//! * [`metrics`] — threshold selection and operating points.
//! * [`results`] — the `results.json` contract and deterministic rendering.
//! * [`digest`] — dependency-free SHA-256 for the corpus digest.
//! * [`error`] — the single crate error type; library code never panics on
//!   I/O or parsing.
//!
//! Determinism is the load-bearing property: the detector is a pure function
//! of the case text, corpus order is sorted by case id, and `results.json`
//! carries no timestamp, hostname, or absolute path — so the committed
//! results file can be re-verified byte-for-byte in CI with `--check`.

#![warn(missing_docs)]

pub mod corpus;
pub mod detector;
pub mod digest;
pub mod error;
pub mod metrics;
pub mod results;

pub use corpus::{CaseRecord, Corpus, Label, Source};
pub use detector::{Detector, Evidence, UnicodeClasses, Verdict};
pub use error::BenchError;
pub use metrics::{OperatingPoint, ScoredCase};
pub use results::ResultsReport;
