//! Corpus discovery, parsing, validation, and the raw-file lint.
//!
//! This module implements `corpus/SCHEMA.md` exactly:
//!
//! * family files are discovered by walking `cases/` recursively for `*.json`,
//!   sorted by path — the filesystem is the manifest;
//! * the raw-file lint runs **before** parsing: any codepoint on the banned
//!   list appearing literally (rather than as a `\uXXXX` escape) fails the
//!   file, with the codepoint and byte offset, so corpus diffs stay readable;
//! * parsing is strict (`deny_unknown_fields`), so a typo'd field is an error
//!   and never a silent default;
//! * every semantic rule in SCHEMA.md is checked, and the loaded corpus is
//!   exposed in one deterministic order: cases sorted by id.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::digest;
use crate::error::{validation, BenchError, Result};

/// The label of a family, and therefore of every case in it. Deserialises
/// strictly: anything other than `"attack"` or `"benign"` is a parse error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Label {
    /// The case is an attack: the detector is expected to fire.
    Attack,
    /// The case is benign: the detector is expected to stay silent.
    Benign,
}

impl Label {
    /// The lowercase string form used in JSON and in the summary table.
    pub fn as_str(self) -> &'static str {
        match self {
            Label::Attack => "attack",
            Label::Benign => "benign",
        }
    }
}

/// A case as written inside a family file (SCHEMA.md "Case schema").
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    /// Kebab-case id, globally unique across the whole corpus, following the
    /// SCHEMA.md `<family>-<nn>` convention: the family name, then a
    /// zero-padded all-digit suffix of one shared width per family.
    pub id: String,
    /// Short human-readable label (under 80 characters).
    pub title: String,
    /// The text fed to the detector verbatim.
    pub text: String,
    /// One sentence on why this text carries this label.
    pub rationale: String,
    /// Attribution: which registered source this text comes from.
    pub source: SourceRef,
}

/// The `source` object on a case.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRef {
    /// Must resolve to an `id` in `sources.json`.
    pub id: String,
    /// Optional free-text pointer within the source (page, heading, commit).
    #[serde(default)]
    pub locator: Option<String>,
}

/// A family file (SCHEMA.md "Family file schema"): one label, many cases.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Family {
    /// Kebab-case, unique across the corpus, and equal to the file stem.
    pub family: String,
    /// Exactly `attack` or `benign`; a family is never mixed.
    pub label: Label,
    /// One or two sentences on what this family is and why it belongs.
    pub description: String,
    /// The cases; required to be non-empty.
    pub cases: Vec<Case>,
}

/// A source-registry entry from `sources.json`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    /// Kebab-case id referenced by case `source.id` fields.
    pub id: String,
    /// Human-readable description of where the text came from.
    pub name: String,
    /// SPDX licence identifier, e.g. `CC0-1.0` (British spelling, deliberately).
    pub licence: String,
    /// URL where the licence text can be read.
    pub licence_url: String,
    /// Where the source itself can be found.
    #[serde(default)]
    pub url: Option<String>,
    /// Anything else a reviewer should know about provenance.
    #[serde(default)]
    pub note: Option<String>,
}

/// The top level of `sources.json`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourcesFile {
    schema_version: u32,
    sources: Vec<Source>,
}

/// One case as exposed by a loaded [`Corpus`]: the case fields plus the
/// family it came from and that family's label.
#[derive(Debug, Clone)]
pub struct CaseRecord {
    /// Kebab-case id, globally unique.
    pub id: String,
    /// Family the case belongs to.
    pub family: String,
    /// Label inherited from the family (never from the directory path).
    pub label: Label,
    /// Short human-readable label.
    pub title: String,
    /// The text fed to the detector verbatim.
    pub text: String,
    /// Why this text carries this label.
    pub rationale: String,
    /// Resolved source id (guaranteed to exist in [`Corpus::sources`]).
    pub source_id: String,
    /// Optional locator within the source.
    pub source_locator: Option<String>,
}

/// One raw file as read from disk, kept so the corpus digest covers exactly
/// the bytes that were validated.
#[derive(Debug, Clone)]
pub(crate) struct RawFile {
    /// Path relative to the corpus root, with `/` separators.
    pub(crate) rel_path: String,
    /// The exact bytes on disk.
    pub(crate) bytes: Vec<u8>,
}

/// A fully loaded, validated corpus.
///
/// Determinism contract: `cases` is sorted by id (plain lexicographic),
/// `families` by family name, `sources` by id. Nothing in here depends on
/// filesystem iteration order.
#[derive(Debug, Clone)]
pub struct Corpus {
    /// Source registry entries, sorted by id.
    pub sources: Vec<Source>,
    /// Family files, sorted by family name.
    pub families: Vec<Family>,
    /// Every case from every family, sorted by id.
    pub cases: Vec<CaseRecord>,
    /// Raw bytes in digest order: family files by sorted relative path, then
    /// `sources.json`.
    raw_files: Vec<RawFile>,
}

impl Corpus {
    /// Loads and validates a corpus rooted at `corpus_dir` (the directory
    /// containing `SCHEMA.md`, `sources.json`, and `cases/`).
    pub fn load(corpus_dir: &Path) -> Result<Corpus> {
        let sources_path = corpus_dir.join("sources.json");
        let sources_raw = read_bytes(&sources_path)?;
        let sources_text = decode_utf8(&sources_path, &sources_raw)?;
        let sources_file: SourcesFile = parse_json(&sources_path, &sources_text)?;
        if sources_file.schema_version != SCHEMA_VERSION {
            return Err(validation(
                &sources_path,
                format!(
                    "unsupported sources.json schema_version {}: this runner implements version {}",
                    sources_file.schema_version, SCHEMA_VERSION
                ),
            ));
        }
        validate_sources(&sources_path, &sources_file.sources)?;

        let cases_dir = corpus_dir.join("cases");
        let mut family_paths = discover_family_files(&cases_dir)?;
        family_paths.sort_by(|a, b| a.0.cmp(&b.0));

        let mut raw_files = Vec::new();
        let mut families: Vec<Family> = Vec::new();
        let mut family_names: HashSet<String> = HashSet::new();
        let mut case_ids: HashSet<String> = HashSet::new();
        let source_ids: HashSet<&str> =
            sources_file.sources.iter().map(|s| s.id.as_str()).collect();

        for (rel_path, abs_path) in family_paths {
            let raw = read_bytes(&abs_path)?;
            let text = decode_utf8(&abs_path, &raw)?;
            // The raw-file lint runs before parsing: this is what keeps
            // corpus diffs reviewable. See SCHEMA.md, "The escaping rule".
            if let Some((codepoint, offset)) = first_banned_codepoint(&text) {
                return Err(BenchError::BannedCodepoint {
                    path: abs_path,
                    codepoint,
                    byte_offset: offset,
                });
            }
            let family: Family = parse_json(&abs_path, &text)?;
            // The duplicate-name check runs before per-file validation: with
            // the file-stem rule two files can only collide on a declared
            // name, and the collision, not the stem mismatch, is the error a
            // reader needs to see.
            if !family_names.insert(family.family.clone()) {
                return Err(validation(
                    &abs_path,
                    format!(
                        "duplicate family name '{}': each family must appear in exactly one file",
                        family.family
                    ),
                ));
            }
            validate_family(&rel_path, &abs_path, &family)?;
            let mut suffix_widths: Vec<(&str, usize)> = Vec::new();
            for case in &family.cases {
                validate_case(&rel_path, &abs_path, &family, case)?;
                if !case_ids.insert(case.id.clone()) {
                    return Err(validation(
                        &abs_path,
                        format!(
                            "duplicate case id '{}': ids are globally unique across the corpus",
                            case.id
                        ),
                    ));
                }
                if !source_ids.contains(case.source.id.as_str()) {
                    return Err(validation(
                        &abs_path,
                        format!(
                            "case '{}': source id '{}' does not resolve to an entry in sources.json",
                            case.id, case.source.id
                        ),
                    ));
                }
                // unwrap_or_default is unreachable: validate_case has already
                // required the `<family>-<nn>` shape.
                let suffix = case_id_suffix(&family.family, &case.id).unwrap_or_default();
                suffix_widths.push((case.id.as_str(), suffix.len()));
            }
            // SCHEMA.md, "Determinism": the numeric suffix is zero-padded to a
            // fixed width within a family so lexicographic order (the only
            // ordering in the benchmark) and numeric order agree.
            let widths: HashSet<usize> = suffix_widths.iter().map(|(_, w)| *w).collect();
            if widths.len() > 1 {
                let listing = suffix_widths
                    .iter()
                    .map(|(id, w)| format!("'{id}' (width {w})"))
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(validation(
                    &abs_path,
                    format!(
                        "family '{}': case ids mix numeric-suffix widths: {}; SCHEMA.md requires one zero-padded width per family so lexicographic order and numeric order agree",
                        family.family, listing
                    ),
                ));
            }
            raw_files.push(RawFile {
                rel_path,
                bytes: raw,
            });
            families.push(family);
        }

        families.sort_by(|a, b| a.family.cmp(&b.family));

        let mut cases: Vec<CaseRecord> = Vec::new();
        for family in &families {
            for case in &family.cases {
                cases.push(CaseRecord {
                    id: case.id.clone(),
                    family: family.family.clone(),
                    label: family.label,
                    title: case.title.clone(),
                    text: case.text.clone(),
                    rationale: case.rationale.clone(),
                    source_id: case.source.id.clone(),
                    source_locator: case.source.locator.clone(),
                });
            }
        }
        // The only ordering in the benchmark: plain lexicographic by id.
        cases.sort_by(|a, b| a.id.cmp(&b.id));

        raw_files.push(RawFile {
            rel_path: "sources.json".to_string(),
            bytes: sources_raw,
        });

        Ok(Corpus {
            sources: sources_file.sources,
            families,
            cases,
            raw_files,
        })
    }

    /// The corpus digest, per SCHEMA.md: SHA-256 over, for each family file
    /// in sorted relative-path order, the relative path (UTF-8), a `0x00`
    /// byte, the raw file bytes, a `0x00` byte — then `sources.json` the same
    /// way. Reported as `"sha256:<hex>"`.
    ///
    /// Covers exactly the bytes that were validated, so any corpus edit that
    /// changes a case also changes the digest recorded in `results.json`.
    pub fn digest(&self) -> String {
        let mut stream = Vec::new();
        for file in &self.raw_files {
            stream.extend_from_slice(file.rel_path.as_bytes());
            stream.push(0x00);
            stream.extend_from_slice(&file.bytes);
            stream.push(0x00);
        }
        format!("sha256:{}", digest::to_hex(&digest::sha256(&stream)))
    }
}

/// The schema version this runner implements, for `sources.json`.
pub(crate) const SCHEMA_VERSION: u32 = 1;

/// The banned-codepoint table from SCHEMA.md, "The escaping rule": these
/// codepoints must appear in corpus JSON only as `\uXXXX` escapes (as a
/// UTF-16 surrogate pair above U+FFFF), never as literal UTF-8 bytes.
const BANNED_CODEPOINT_RANGES: &[(u32, u32)] = &[
    (0x00AD, 0x00AD),     // soft hyphen
    (0x061C, 0x061C),     // Arabic letter mark
    (0x115F, 0x1160),     // Hangul fillers
    (0x180E, 0x180E),     // Mongolian vowel separator
    (0x200B, 0x200F),     // ZWSP, ZWNJ, ZWJ, LRM, RLM
    (0x202A, 0x202E),     // bidi embedding and override controls
    (0x2060, 0x2064),     // word joiner and invisible operators
    (0x2066, 0x2069),     // bidi isolates
    (0x3164, 0x3164),     // Hangul filler
    (0xFE00, 0xFE0F),     // variation selectors
    (0xFEFF, 0xFEFF),     // BOM / zero-width no-break space
    (0xFFA0, 0xFFA0),     // halfwidth Hangul filler
    (0xE0000, 0xE007F),   // tag characters
    (0xE0100, 0xE01EF),   // variation selectors supplement
    (0xE000, 0xF8FF),     // private use area
    (0xF0000, 0xFFFFD),   // supplementary private use area A
    (0x100000, 0x10FFFD), // supplementary private use area B
];

/// Returns the first banned codepoint appearing literally in `text`, with its
/// byte offset. `None` means the file passes the raw-file lint.
pub fn first_banned_codepoint(text: &str) -> Option<(char, usize)> {
    for (offset, ch) in text.char_indices() {
        let cp = ch as u32;
        if BANNED_CODEPOINT_RANGES
            .iter()
            .any(|&(lo, hi)| cp >= lo && cp <= hi)
        {
            return Some((ch, offset));
        }
    }
    None
}

/// True when `s` matches `^[a-z0-9]+(-[a-z0-9]+)*$` (SCHEMA.md "Identifiers").
pub fn is_kebab_case(s: &str) -> bool {
    !s.is_empty()
        && s.split('-').all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        })
}

/// Recursively walks `cases_dir` for `*.json`, returning `(relative path with
/// '/' separators, absolute path)` pairs. The caller sorts them.
fn discover_family_files(cases_dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut out = Vec::new();
    let mut stack = vec![cases_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir).map_err(|e| BenchError::Io {
            path: dir.clone(),
            source: e,
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| BenchError::Io {
                path: dir.clone(),
                source: e,
            })?;
            let path = entry.path();
            let file_type = entry.file_type().map_err(|e| BenchError::Io {
                path: path.clone(),
                source: e,
            })?;
            if file_type.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "json") {
                let rel = path
                    .strip_prefix(cases_dir)
                    .unwrap_or(path.as_path())
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((format!("cases/{rel}"), path));
            }
        }
    }
    Ok(out)
}

fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| BenchError::Io {
        path: path.to_path_buf(),
        source: e,
    })
}

fn decode_utf8(path: &Path, bytes: &[u8]) -> Result<String> {
    std::str::from_utf8(bytes)
        .map(str::to_string)
        .map_err(|e| BenchError::ReadUtf8 {
            path: path.to_path_buf(),
            source: e,
        })
}

fn parse_json<T: for<'de> Deserialize<'de>>(path: &Path, text: &str) -> Result<T> {
    serde_json::from_str(text).map_err(|e| BenchError::ParseJson {
        path: path.to_path_buf(),
        source: e,
    })
}

fn validate_sources(path: &Path, sources: &[Source]) -> Result<()> {
    let mut seen: HashSet<&str> = HashSet::new();
    for source in sources {
        if source.id.trim().is_empty() {
            return Err(validation(path, "source with empty id".to_string()));
        }
        if !is_kebab_case(&source.id) {
            return Err(validation(
                path,
                format!("source id '{}' is not kebab-case", source.id),
            ));
        }
        if !seen.insert(source.id.as_str()) {
            return Err(validation(
                path,
                format!("duplicate source id '{}'", source.id),
            ));
        }
        if source.name.trim().is_empty() {
            return Err(validation(
                path,
                format!("source '{}': empty name", source.id),
            ));
        }
        if source.licence.trim().is_empty() {
            return Err(validation(
                path,
                format!("source '{}': empty licence", source.id),
            ));
        }
        if source.licence_url.trim().is_empty() {
            return Err(validation(
                path,
                format!("source '{}': empty licence_url", source.id),
            ));
        }
    }
    Ok(())
}

fn validate_family(rel_path: &str, abs_path: &Path, family: &Family) -> Result<()> {
    if !is_kebab_case(&family.family) {
        return Err(validation(
            abs_path,
            format!("family name '{}' is not kebab-case", family.family),
        ));
    }
    let stem = abs_path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    if family.family != stem {
        return Err(validation(
            abs_path,
            format!(
                "family '{}' does not match file stem '{stem}' (cases/{})",
                family.family, rel_path
            ),
        ));
    }
    if family.description.trim().is_empty() {
        return Err(validation(
            abs_path,
            format!("family '{}': empty description", family.family),
        ));
    }
    if family.cases.is_empty() {
        return Err(validation(
            abs_path,
            format!("family '{}': cases array is empty", family.family),
        ));
    }
    Ok(())
}

/// The `<nn>` suffix of a case id under the SCHEMA.md `<family>-<nn>`
/// convention: everything after `family` and the hyphen that follows it.
/// `None` when the id does not start with the family name followed by `-`.
fn case_id_suffix<'a>(family: &str, id: &'a str) -> Option<&'a str> {
    id.strip_prefix(family)
        .and_then(|rest| rest.strip_prefix('-'))
}

fn validate_case(rel_path: &str, abs_path: &Path, family: &Family, case: &Case) -> Result<()> {
    let ctx = |message: String| -> BenchError {
        BenchError::Validation {
            message: format!("{} (case '{}'): {}", abs_path.display(), case.id, message),
        }
    };
    if case.id.trim().is_empty() {
        return Err(validation(
            abs_path,
            format!("cases/{rel_path}: case with empty id"),
        ));
    }
    if !is_kebab_case(&case.id) {
        return Err(ctx(format!("id '{}' is not kebab-case", case.id)));
    }
    // SCHEMA.md, "Case schema" and "Checklist": every id follows
    // `<family>-<nn>` — the family name, then a zero-padded all-digit suffix.
    // Without this, a `foo-2` / `foo-10` pair loads cleanly and silently
    // scrambles the family's ordering, which is the only ordering in the
    // benchmark.
    let Some(suffix) = case_id_suffix(&family.family, &case.id) else {
        return Err(ctx(format!(
            "id must start with its family name '{}' followed by a hyphen; SCHEMA.md requires the <family>-<nn> convention",
            family.family
        )));
    };
    if suffix.is_empty() || !suffix.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ctx(format!(
            "id suffix '{suffix}' is not all digits; SCHEMA.md requires <family>-<nn> with a numeric suffix"
        )));
    }
    if suffix.len() < 2 {
        return Err(ctx(format!(
            "id suffix '{suffix}' is fewer than two digits; SCHEMA.md requires zero-padding (e.g. {}-01) so lexicographic order and numeric order agree",
            family.family
        )));
    }
    if case.title.trim().is_empty() {
        return Err(ctx("empty title".to_string()));
    }
    if case.title.chars().count() >= 80 {
        return Err(ctx(format!(
            "title is {} characters; SCHEMA.md requires under 80",
            case.title.chars().count()
        )));
    }
    if case.text.trim().is_empty() {
        return Err(ctx("empty text".to_string()));
    }
    if case.rationale.trim().is_empty() {
        return Err(ctx("empty rationale".to_string()));
    }
    if case.source.id.trim().is_empty() {
        return Err(ctx("empty source.id".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_SOURCES: &str = r#"{
  "schema_version": 1,
  "sources": [
    {
      "id": "test-source",
      "name": "A test source",
      "licence": "CC0-1.0",
      "licence_url": "https://example.com/licence"
    }
  ]
}"#;

    /// Writes a minimal corpus fixture and returns its root directory.
    /// `families` maps a filename under `cases/` (subdirectories allowed) to
    /// file contents. All paths live under the OS temp dir.
    fn fixture(name: &str, families: &[(&str, &str)]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "promptdecode-bench-corpus-test-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("cases")).unwrap();
        fs::write(dir.join("sources.json"), VALID_SOURCES).unwrap();
        for (rel, body) in families {
            let path = dir.join("cases").join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, body).unwrap();
        }
        dir
    }

    fn family_json(family: &str, label: &str, cases: &str) -> String {
        format!(
            r#"{{
  "family": "{family}",
  "label": "{label}",
  "description": "A test family.",
  "cases": [{cases}]
}}"#
        )
    }

    fn case_json(id: &str, text: &str) -> String {
        format!(
            r#"{{
      "id": "{id}",
      "title": "A test case",
      "text": "{text}",
      "rationale": "Because this is a test.",
      "source": {{"id": "test-source"}}
    }}"#
        )
    }

    #[test]
    fn loads_a_valid_corpus_sorted_by_case_id() {
        let dir = fixture(
            "valid",
            &[
                (
                    "benign/b-family.json",
                    &family_json(
                        "b-family",
                        "benign",
                        &case_json("b-family-01", "hello world"),
                    ),
                ),
                (
                    "attack/a-family.json",
                    &family_json("a-family", "attack", &case_json("a-family-01", "hidden")),
                ),
            ],
        );
        let corpus = Corpus::load(&dir).unwrap();
        let ids: Vec<&str> = corpus.cases.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["a-family-01", "b-family-01"]);
        assert_eq!(corpus.cases[0].label, Label::Attack);
        assert_eq!(corpus.cases[1].label, Label::Benign);
        assert_eq!(corpus.families.len(), 2);
        // Digest is stable across loads of the same bytes.
        assert_eq!(corpus.digest(), Corpus::load(&dir).unwrap().digest());
        assert!(corpus.digest().starts_with("sha256:"));
    }

    #[test]
    fn rejects_duplicate_case_ids() {
        // Two files can no longer collide: the <family>-<nn> rule pins every
        // id to its family, so a genuine duplicate can only occur within one
        // family's file.
        let dir = fixture(
            "dup-case-id",
            &[(
                "attack/one.json",
                &family_json(
                    "one",
                    "attack",
                    &format!("{},{}", case_json("one-01", "a"), case_json("one-01", "b")),
                ),
            )],
        );
        let err = Corpus::load(&dir).unwrap_err().to_string();
        assert!(err.contains("duplicate case id 'one-01'"), "{err}");
    }

    #[test]
    fn rejects_unresolvable_source_id() {
        let dir = fixture(
            "bad-source",
            &[(
                "attack/lonely.json",
                &family_json(
                    "lonely",
                    "attack",
                    &case_json("lonely-01", "text")
                        .replace("\"test-source\"", "\"missing-source\""),
                ),
            )],
        );
        let err = Corpus::load(&dir).unwrap_err().to_string();
        assert!(
            err.contains("case 'lonely-01': source id 'missing-source' does not resolve"),
            "{err}"
        );
    }

    #[test]
    fn rejects_literal_banned_codepoint_and_names_offset() {
        // A literal U+200B written straight into the JSON text field.
        let body = family_json(
            "sneaky",
            "attack",
            &format!(
                r#"{{
      "id": "sneaky-01",
      "title": "Literal zero-width space",
      "text": "ab{}cd",
      "rationale": "Contains a literal banned codepoint.",
      "source": {{"id": "test-source"}}
    }}"#,
                '\u{200B}'
            ),
        );
        let dir = fixture("banned-literal", &[("attack/sneaky.json", &body)]);
        let err = Corpus::load(&dir).unwrap_err().to_string();
        assert!(err.contains("U+200B"), "{err}");
        assert!(err.contains("byte offset"), "{err}");
    }

    #[test]
    fn rejects_escaped_aware_but_checks_are_after_lint_order() {
        // The same codepoint written as a \\u escape must load fine.
        let body = family_json("escaped", "attack", &case_json("escaped-01", "ab\\u200Bcd"));
        let dir = fixture("banned-escaped", &[("attack/escaped.json", &body)]);
        let corpus = Corpus::load(&dir).unwrap();
        assert_eq!(corpus.cases[0].text, "ab\u{200B}cd");
    }

    #[test]
    fn rejects_family_not_matching_file_stem() {
        let dir = fixture(
            "stem-mismatch",
            &[(
                "attack/other-name.json",
                &family_json(
                    "declared-name",
                    "attack",
                    &case_json("declared-name-01", "x"),
                ),
            )],
        );
        let err = Corpus::load(&dir).unwrap_err().to_string();
        assert!(
            err.contains("family 'declared-name' does not match file stem 'other-name'"),
            "{err}"
        );
    }

    #[test]
    fn rejects_unknown_json_field() {
        let body = format!(
            r#"{{
  "family": "typo",
  "label": "attack",
  "description": "Has a typo'd field.",
  "cases": [{}],
  "extra_field": true
}}"#,
            case_json("typo-01", "x")
        );
        let dir = fixture("unknown-field", &[("attack/typo.json", &body)]);
        match Corpus::load(&dir) {
            Err(BenchError::ParseJson { source, .. }) => {
                assert!(source.to_string().contains("unknown field"), "{source}");
            }
            other => panic!("expected ParseJson error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_text() {
        let dir = fixture(
            "empty-text",
            &[(
                "attack/hollow.json",
                &family_json("hollow", "attack", &case_json("hollow-01", "  ")),
            )],
        );
        let err = Corpus::load(&dir).unwrap_err().to_string();
        assert!(err.contains("(case 'hollow-01'): empty text"), "{err}");
    }

    #[test]
    fn rejects_unknown_label_and_missing_fields_via_strict_parse() {
        let body = family_json("mislabeled", "ambiguous", &case_json("mislabeled-01", "x"));
        let dir = fixture("bad-label", &[("attack/mislabeled.json", &body)]);
        match Corpus::load(&dir) {
            Err(BenchError::ParseJson { .. }) => {}
            other => panic!("expected ParseJson error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_family_name_across_files() {
        let dir = fixture(
            "dup-family",
            &[
                (
                    "attack/clone.json",
                    &family_json("clone", "attack", &case_json("clone-01", "a")),
                ),
                (
                    "benign/clone-copy.json",
                    &family_json("clone", "benign", &case_json("clone-copy-01", "b")),
                ),
            ],
        );
        let err = Corpus::load(&dir).unwrap_err().to_string();
        assert!(err.contains("duplicate family name 'clone'"), "{err}");
    }

    #[test]
    fn rejects_bad_source_registry() {
        let dir = fixture("bad-registry", &[]);
        fs::write(
            dir.join("sources.json"),
            r#"{
  "schema_version": 1,
  "sources": [
    {"id": "dup", "name": "n", "licence": "MIT", "licence_url": "https://x"},
    {"id": "dup", "name": "n", "licence": "MIT", "licence_url": "https://x"}
  ]
}"#,
        )
        .unwrap();
        let err = Corpus::load(&dir).unwrap_err().to_string();
        assert!(err.contains("duplicate source id 'dup'"), "{err}");
    }

    #[test]
    fn rejects_non_kebab_case_case_id() {
        let dir = fixture(
            "bad-id",
            &[(
                "attack/kebab.json",
                &family_json("kebab", "attack", &case_json("kebab_01", "x")),
            )],
        );
        let err = Corpus::load(&dir).unwrap_err().to_string();
        assert!(err.contains("not kebab-case"), "{err}");
    }

    #[test]
    fn accepts_family_prefixed_padded_ids() {
        // Width 2 and width 3 are both fine, as long as each family is
        // internally consistent.
        let dir = fixture(
            "good-ids",
            &[
                (
                    "attack/foo.json",
                    &family_json("foo", "attack", &case_json("foo-01", "a")),
                ),
                (
                    "benign/bar.json",
                    &family_json(
                        "bar",
                        "benign",
                        &format!(
                            "{},{}",
                            case_json("bar-001", "b"),
                            case_json("bar-002", "c")
                        ),
                    ),
                ),
            ],
        );
        let corpus = Corpus::load(&dir).unwrap();
        assert_eq!(corpus.cases.len(), 3);
    }

    #[test]
    fn rejects_id_not_prefixed_with_its_family_name() {
        let dir = fixture(
            "wrong-family-prefix",
            &[(
                "attack/foo.json",
                &family_json("foo", "attack", &case_json("bar-01", "x")),
            )],
        );
        let err = Corpus::load(&dir).unwrap_err().to_string();
        assert!(err.contains("(case 'bar-01')"), "{err}");
        assert!(
            err.contains("family name 'foo'"),
            "error must name the family: {err}"
        );
    }

    #[test]
    fn rejects_unpadded_numeric_suffix() {
        let dir = fixture(
            "unpadded-suffix",
            &[(
                "attack/foo.json",
                &family_json("foo", "attack", &case_json("foo-2", "x")),
            )],
        );
        let err = Corpus::load(&dir).unwrap_err().to_string();
        assert!(err.contains("(case 'foo-2')"), "{err}");
        assert!(err.contains("fewer than two digits"), "{err}");
    }

    #[test]
    fn rejects_non_numeric_suffix() {
        let dir = fixture(
            "non-numeric-suffix",
            &[(
                "attack/foo.json",
                &family_json("foo", "attack", &case_json("foo-abc", "x")),
            )],
        );
        let err = Corpus::load(&dir).unwrap_err().to_string();
        assert!(err.contains("(case 'foo-abc')"), "{err}");
        assert!(err.contains("not all digits"), "{err}");
    }

    #[test]
    fn rejects_mixed_suffix_widths_within_a_family() {
        let dir = fixture(
            "mixed-width",
            &[(
                "attack/foo.json",
                &family_json(
                    "foo",
                    "attack",
                    &format!("{},{}", case_json("foo-01", "a"), case_json("foo-001", "b")),
                ),
            )],
        );
        let err = Corpus::load(&dir).unwrap_err().to_string();
        assert!(err.contains("'foo-01' (width 2)"), "{err}");
        assert!(err.contains("'foo-001' (width 3)"), "{err}");
        assert!(err.contains("family 'foo'"), "{err}");
    }

    #[test]
    fn kebab_case_matches_schema_regex() {
        for good in ["a", "ab-12", "unicode-tag-block-07", "0"] {
            assert!(is_kebab_case(good), "{good} should be kebab-case");
        }
        for bad in ["", "-a", "a-", "A", "a_b", "a--b", "ab-CD", "a b"] {
            assert!(!is_kebab_case(bad), "{bad} should not be kebab-case");
        }
    }

    #[test]
    fn lint_finds_each_banned_codepoint_at_the_right_offset() {
        // One representative of each range on the SCHEMA.md list.
        let representatives = [
            '\u{00AD}',
            '\u{061C}',
            '\u{115F}',
            '\u{1160}',
            '\u{180E}',
            '\u{200B}',
            '\u{200F}',
            '\u{202A}',
            '\u{202E}',
            '\u{2060}',
            '\u{2064}',
            '\u{2066}',
            '\u{2069}',
            '\u{3164}',
            '\u{FE00}',
            '\u{FE0F}',
            '\u{FEFF}',
            '\u{FFA0}',
            '\u{E000}',
            '\u{F8FF}',
            '\u{E0000}',
            '\u{E007F}',
            '\u{E0100}',
            '\u{E01EF}',
            '\u{F0000}',
            '\u{FFFFD}',
            '\u{100000}',
            '\u{10FFFD}',
        ];
        for cp in representatives {
            let text = format!("ok\u{00E9}{}", cp);
            let (found, offset) = first_banned_codepoint(&text).unwrap_or_else(|| {
                panic!("U+{:04X} should be flagged", cp as u32);
            });
            assert_eq!(found, cp);
            // "ok" (2 bytes) + U+00E9 (2 bytes) is 4 bytes before the banned codepoint.
            assert_eq!(offset, 4, "wrong byte offset for U+{:04X}", cp as u32);
        }
        // Visible non-ASCII is fine to write literally.
        assert_eq!(
            first_banned_codepoint("caf\u{00E9} \u{4E2D}\u{6587} \u{1F3F4}"),
            None
        );
    }
}
