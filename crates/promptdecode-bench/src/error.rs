//! The single error type for the whole crate.
//!
//! Library code never panics on I/O, decoding, or parsing problems: every
//! failure is a [`BenchError`] carrying enough context (file path, case id,
//! codepoint, offset) to act on without a debugger.

use std::fmt;
use std::path::PathBuf;

/// Everything that can go wrong while loading, validating, scoring, or
/// reporting on a corpus.
#[derive(Debug)]
pub enum BenchError {
    /// A file could not be read from disk.
    Io {
        /// The file that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// A file was read but is not valid UTF-8.
    ReadUtf8 {
        /// The file that is not valid UTF-8.
        path: PathBuf,
        /// The underlying decoding error.
        source: std::str::Utf8Error,
    },
    /// A file parsed as text but not as the JSON shape the schema requires.
    ParseJson {
        /// The file that failed to parse.
        path: PathBuf,
        /// The underlying serde error (includes JSON line/column).
        source: serde_json::Error,
    },
    /// A family file contains a banned codepoint written literally instead of
    /// as a `\uXXXX` escape. This is the raw-file lint from SCHEMA.md.
    BannedCodepoint {
        /// The offending file.
        path: PathBuf,
        /// The banned codepoint that appeared literally.
        codepoint: char,
        /// Byte offset of the codepoint's first UTF-8 byte in the file.
        byte_offset: usize,
    },
    /// A semantic rule from SCHEMA.md was violated. The message names the
    /// file and, where relevant, the case id.
    Validation {
        /// Human-readable description of the violation.
        message: String,
    },
    /// Rendering a report to JSON failed. In practice unreachable for the
    /// plain structs in this crate, but handled rather than unwrapped.
    Serialisation {
        /// Human-readable description of the failure.
        message: String,
    },
}

impl fmt::Display for BenchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BenchError::Io { path, source } => {
                write!(f, "failed to read {}: {}", path.display(), source)
            }
            BenchError::ReadUtf8 { path, source } => {
                write!(f, "{} is not valid UTF-8: {}", path.display(), source)
            }
            BenchError::ParseJson { path, source } => {
                write!(f, "failed to parse {}: {}", path.display(), source)
            }
            BenchError::BannedCodepoint {
                path,
                codepoint,
                byte_offset,
            } => write!(
                f,
                "{} contains literal codepoint U+{:04X} at byte offset {}, which must be written as a \\u escape (see corpus/SCHEMA.md, the escaping rule)",
                path.display(),
                *codepoint as u32,
                byte_offset
            ),
            BenchError::Validation { message } => write!(f, "{message}"),
            BenchError::Serialisation { message } => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for BenchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BenchError::Io { source, .. } => Some(source),
            BenchError::ReadUtf8 { source, .. } => Some(source),
            BenchError::ParseJson { source, .. } => Some(source),
            BenchError::BannedCodepoint { .. } => None,
            BenchError::Validation { .. } => None,
            BenchError::Serialisation { .. } => None,
        }
    }
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, BenchError>;

/// Builds a [`BenchError::Validation`] naming `path` (and optionally a case
/// id) with `message` as the specific complaint.
pub(crate) fn validation(path: &std::path::Path, message: String) -> BenchError {
    BenchError::Validation {
        message: format!("{}: {}", path.display(), message),
    }
}
