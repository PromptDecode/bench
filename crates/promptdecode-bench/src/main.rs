//! The bench CLI. Argument parsing is by hand: the dependency list stays at
//! serde + serde_json.
//!
//! Modes:
//!
//! * default — load, validate, score, write `results.json`, print a summary,
//!   and fail if a baseline recall floor is not met;
//! * `--check` — same computation, writes nothing; fails if the on-disk
//!   results file differs from the freshly computed one or a baseline floor
//!   is violated (the CI entry point);
//! * `--explain <case-id>` — print one case's full audit trail.
//!
//! Exit codes: 0 success, 1 benchmark/baseline/verification failure, 2 usage
//! error.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use promptdecode_bench::corpus::Label;
use promptdecode_bench::detector::UnicodeClasses;
use promptdecode_bench::error::BenchError;
use promptdecode_bench::metrics::{score_corpus, TARGET_FPRS};
use promptdecode_bench::results::{build_report, parse_baseline, render, Baseline};
use promptdecode_bench::{Corpus, Detector, OperatingPoint};

const USAGE: &str =
    "promptdecode-bench: recall at a stated false-positive rate for prompt-smuggling detectors

USAGE:
    promptdecode-bench [--corpus <dir>] [--out <file>] [--baseline <file>]
    promptdecode-bench --check [--corpus <dir>] [--out <file>] [--baseline <file>]
    promptdecode-bench --explain <case-id> [--corpus <dir>]
    promptdecode-bench --help

MODES:
    (default)             Load and validate the corpus, score it, write
                          results.json, print a summary, and exit 1 if any
                          baseline recall floor is not met.
    --check               Recompute everything and write nothing; exit 1 if
                          the on-disk results file differs from the freshly
                          computed one, or if a baseline floor is violated.
                          This is the CI entry point.
    --explain <case-id>   Print one case's label, source, licence, score and
                          full evidence breakdown.

OPTIONS:
    --corpus <dir>        Corpus root (default: <repo>/corpus).
    --out <file>          Results file to write or check (default:
                          <repo>/results.json).
    --baseline <file>     Recall floors (default: <repo>/baseline.json).
    --help                Show this text.

Unknown arguments are an error, not silently ignored.";

/// Parsed command line.
struct Options {
    corpus_dir: PathBuf,
    out_path: PathBuf,
    baseline_path: PathBuf,
    explain: Option<String>,
    check: bool,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let options = match parse_args(&args) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("error: {message}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(options) {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            eprintln!("{failure}");
            ExitCode::FAILURE
        }
    }
}

/// Resolves the repo root from the crate location so `cargo run` works from
/// anywhere in the workspace.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut options = Options {
        corpus_dir: repo_root().join("corpus"),
        out_path: repo_root().join("results.json"),
        baseline_path: repo_root().join("baseline.json"),
        explain: None,
        check: false,
    };
    let mut i = 0usize;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--help" | "-h" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            "--check" => options.check = true,
            "--corpus" => {
                i += 1;
                options.corpus_dir = value_of(arg, args.get(i))?.into();
            }
            "--out" => {
                i += 1;
                options.out_path = value_of(arg, args.get(i))?.into();
            }
            "--baseline" => {
                i += 1;
                options.baseline_path = value_of(arg, args.get(i))?.into();
            }
            "--explain" => {
                i += 1;
                options.explain = Some(value_of(arg, args.get(i))?.to_string());
            }
            other => return Err(format!("unknown argument '{other}'")),
        }
        i += 1;
    }
    if options.explain.is_some() && options.check {
        return Err("--explain and --check cannot be combined".to_string());
    }
    Ok(options)
}

fn value_of<'a>(flag: &str, value: Option<&'a String>) -> Result<&'a str, String> {
    value
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn run(options: Options) -> Result<(), String> {
    if let Some(case_id) = &options.explain {
        return explain_case(&options, case_id);
    }

    let detector = UnicodeClasses;
    let scored = load_and_score(&options.corpus_dir, &detector).map_err(|e| e.to_string())?;
    let report = build_report(&scored.0, &detector, &scored.1);
    let rendered = render(&report).map_err(|e| e.to_string())?;

    if options.check {
        check_against_disk(&options.out_path, &rendered)?;
    } else {
        write_results(&options.out_path, &rendered)?;
        print_summary(&scored.0, &scored.1);
        println!("wrote {}", options.out_path.display());
    }

    check_baseline(&options, &detector, &report.operating_points)
}

/// Loads and scores the corpus, returning `(corpus, scored cases)`.
fn load_and_score(
    corpus_dir: &Path,
    detector: &dyn Detector,
) -> Result<(Corpus, Vec<promptdecode_bench::ScoredCase>), BenchError> {
    let corpus = Corpus::load(corpus_dir)?;
    let scored = score_corpus(&corpus, detector);
    Ok((corpus, scored))
}

fn write_results(out_path: &Path, rendered: &str) -> Result<(), String> {
    std::fs::write(out_path, rendered)
        .map_err(|e| format!("failed to write {}: {e}", out_path.display()))
}

/// Compares freshly rendered results against the file on disk, naming the
/// first JSON path that differs.
fn check_against_disk(out_path: &Path, rendered: &str) -> Result<(), String> {
    let on_disk = match std::fs::read_to_string(out_path) {
        Ok(content) => content,
        Err(e) => {
            return Err(format!(
                "{} does not exist yet (or cannot be read: {e}). Run the bench without --check and commit the results file it writes.",
                out_path.display()
            ));
        }
    };
    if on_disk == rendered {
        return Ok(());
    }
    let detail = match (
        serde_json::from_str::<serde_json::Value>(&on_disk),
        serde_json::from_str::<serde_json::Value>(rendered),
    ) {
        (Ok(old), Ok(new)) => first_difference("$", &old, &new).unwrap_or_else(|| {
            "contents are equal as JSON but differ as bytes (formatting or key order)".to_string()
        }),
        _ => "the file is not parseable as JSON".to_string(),
    };
    Err(format!(
        "{} differs from the freshly computed results at {}\nre-run the bench without --check and commit the updated results file",
        out_path.display(),
        detail
    ))
}

/// Finds the first differing path between two JSON values, e.g.
/// `$.operating_points[1].recall`.
fn first_difference(
    path: &str,
    old: &serde_json::Value,
    new: &serde_json::Value,
) -> Option<String> {
    match (old, new) {
        (serde_json::Value::Object(old_map), serde_json::Value::Object(new_map)) => {
            let mut keys: Vec<&String> = old_map.keys().chain(new_map.keys()).collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                let child_old = old_map.get(key).unwrap_or(&serde_json::Value::Null);
                let child_new = new_map.get(key).unwrap_or(&serde_json::Value::Null);
                if let Some(found) =
                    first_difference(&format!("{path}.{key}"), child_old, child_new)
                {
                    return Some(found);
                }
            }
            None
        }
        (serde_json::Value::Array(old_list), serde_json::Value::Array(new_list)) => {
            for i in 0..old_list.len().max(new_list.len()) {
                let child_old = old_list.get(i).unwrap_or(&serde_json::Value::Null);
                let child_new = new_list.get(i).unwrap_or(&serde_json::Value::Null);
                if let Some(found) = first_difference(&format!("{path}[{i}]"), child_old, child_new)
                {
                    return Some(found);
                }
            }
            None
        }
        _ => {
            if old == new {
                None
            } else {
                Some(format!(
                    "{path}: on disk {}, computed {}",
                    abbreviate(old),
                    abbreviate(new)
                ))
            }
        }
    }
}

fn abbreviate(value: &serde_json::Value) -> String {
    let text = value.to_string();
    if text.len() > 80 {
        format!("{}...", &text[..80])
    } else {
        text
    }
}

/// Fails on any baseline recall floor violation, naming the operating point,
/// the baseline value, and the achieved value.
fn check_baseline(
    options: &Options,
    detector: &dyn Detector,
    operating_points: &[OperatingPoint],
) -> Result<(), String> {
    let text = match std::fs::read_to_string(&options.baseline_path) {
        Ok(text) => text,
        Err(e) => {
            println!(
                "note: no baseline at {} ({e}); skipping recall-floor check",
                options.baseline_path.display()
            );
            return Ok(());
        }
    };
    let baseline: Baseline = parse_baseline(&text).map_err(|e| e.to_string())?;
    let violations = baseline_violations(&baseline, detector.id(), operating_points);
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations.join("\n"))
    }
}

/// Every way `baseline` fails to gate `operating_points`: a floor that is not
/// met, and — just as fatal — a results operating point with no floor at all.
/// A floor going missing from baseline.json must shrink the regression gate
/// loudly, never silently.
fn baseline_violations(
    baseline: &Baseline,
    detector_id: &str,
    operating_points: &[OperatingPoint],
) -> Vec<String> {
    if baseline.detector != detector_id {
        return vec![format!(
            "baseline.json targets detector '{}' but this bench ran '{}'; the floors do not apply",
            baseline.detector, detector_id
        )];
    }
    let mut violations = Vec::new();
    for floor in &baseline.operating_points {
        let op = operating_points
            .iter()
            .find(|op| op.target_fpr == floor.target_fpr);
        match op {
            None => violations.push(format!(
                "baseline violation at target_fpr={}: the results contain no such operating point",
                floor.target_fpr
            )),
            Some(op) => {
                if op.recall < floor.min_recall {
                    violations.push(format!(
                        "baseline violation at target_fpr={}: min_recall={}, achieved recall={} (missed: {})",
                        floor.target_fpr,
                        floor.min_recall,
                        op.recall,
                        if op.missed_attack_cases.is_empty() {
                            "none".to_string()
                        } else {
                            op.missed_attack_cases.join(", ")
                        }
                    ));
                }
            }
        }
    }
    for op in operating_points {
        if !baseline
            .operating_points
            .iter()
            .any(|floor| floor.target_fpr == op.target_fpr)
        {
            violations.push(format!(
                "baseline violation at target_fpr={}: baseline.json defines no floor for this operating point, so the regression gate does not cover it",
                op.target_fpr
            ));
        }
    }
    violations
}

/// Prints the human-readable summary table.
fn print_summary(corpus: &Corpus, scored: &[promptdecode_bench::ScoredCase]) {
    let report = build_report(corpus, &UnicodeClasses, scored);
    println!(
        "detector: {} {} over corpus {} ({})",
        report.detector.id, report.detector.version, report.corpus.name, report.corpus.digest
    );
    println!(
        "corpus: {} cases ({} attack / {} benign), {} families, {} sources",
        report.corpus.cases.total,
        report.corpus.cases.attack,
        report.corpus.cases.benign,
        report.corpus.families.len(),
        report.corpus.sources.len()
    );
    println!(
        "resolution: {} benign cases -> finest non-zero FPR this corpus can express is {}",
        report.resolution.benign_cases, report.resolution.finest_nonzero_fpr
    );
    println!();
    println!(
        "{:<12} {:>12} {:>10} {:>10} {:>5} {:>5} {:>5} {:>5}",
        "target FPR", "threshold", "recall", "FPR", "TP", "FN", "FP", "TN"
    );
    for op in &report.operating_points {
        println!(
            "{:<12} {:>12} {:>10} {:>10} {:>5} {:>5} {:>5} {:>5}",
            format!("{}", op.target_fpr),
            threshold_text(op.threshold),
            format!("{:.6}", op.recall),
            format!("{:.6}", op.false_positive_rate),
            op.counts.true_positives,
            op.counts.false_negatives,
            op.counts.false_positives,
            op.counts.true_negatives,
        );
    }
    println!();

    let mut noisy_benign: Vec<(&str, f64, Vec<String>)> = scored
        .iter()
        .filter(|c| c.label == Label::Benign && c.score > 0.0)
        .map(|c| {
            let verdict = UnicodeClasses.score(corpus_text(corpus, &c.id));
            let classes = verdict
                .evidence
                .iter()
                .map(|e| e.class.clone())
                .collect::<Vec<_>>();
            (c.id.as_str(), c.score, classes)
        })
        .collect();
    noisy_benign.sort_by(|a, b| a.0.cmp(b.0));
    if noisy_benign.is_empty() {
        println!("benign cases scoring above 0.0: none");
    } else {
        println!("benign cases scoring above 0.0:");
        for (id, score, classes) in noisy_benign {
            println!("  {id}: score {score} ({})", classes.join(", "));
        }
    }

    let mut silent_attacks: Vec<&str> = scored
        .iter()
        .filter(|c| c.label == Label::Attack && c.score == 0.0)
        .map(|c| c.id.as_str())
        .collect();
    silent_attacks.sort();
    if silent_attacks.is_empty() {
        println!("attack cases scoring 0.0 (complete misses): none");
    } else {
        println!(
            "attack cases scoring 0.0 (complete misses): {}",
            silent_attacks.join(", ")
        );
    }
    println!(
        "target FPRs evaluated: {}",
        TARGET_FPRS
            .iter()
            .map(|t| format!("{t}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
}

/// Looks up a case's text for the summary's evidence breakdown.
fn corpus_text<'a>(corpus: &'a Corpus, id: &str) -> &'a str {
    corpus
        .cases
        .iter()
        .find(|c| c.id == id)
        .map(|c| c.text.as_str())
        .unwrap_or("")
}

fn threshold_text(threshold: f64) -> String {
    if threshold.is_infinite() {
        "inf".to_string()
    } else {
        format!("{threshold}")
    }
}

/// The `--explain` mode: one case's full audit trail.
fn explain_case(options: &Options, case_id: &str) -> Result<(), String> {
    let detector = UnicodeClasses;
    let corpus = Corpus::load(&options.corpus_dir).map_err(|e| e.to_string())?;
    let case = corpus
        .cases
        .iter()
        .find(|c| c.id == case_id)
        .ok_or_else(|| {
            format!(
                "no case with id '{case_id}' in the corpus at {}",
                options.corpus_dir.display()
            )
        })?;
    let source = corpus.sources.iter().find(|s| s.id == case.source_id);
    let verdict = detector.score(&case.text);

    println!("case: {} [{}]", case.id, case.label.as_str());
    println!("family: {}", case.family);
    println!("title: {}", case.title);
    println!("rationale: {}", case.rationale);
    println!("text: {:?}", case.text);
    match source {
        Some(source) => {
            println!("source: {} — {}", source.id, source.name);
            if let Some(url) = &source.url {
                println!("source url: {url}");
            }
            println!("licence: {} ({})", source.licence, source.licence_url);
            match &case.source_locator {
                Some(locator) => println!("locator: {locator}"),
                None => println!("locator: (none)"),
            }
        }
        None => println!("source: {} (not resolved?!)", case.source_id),
    }
    println!("score: {:.6}", verdict.score);
    if verdict.evidence.is_empty() {
        println!("evidence: none");
    } else {
        println!("evidence:");
        for e in &verdict.evidence {
            println!(
                "  {:<34} count {} contribution {:.6} — {}",
                e.class, e.count, e.contribution, e.note
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use promptdecode_bench::metrics::Counts;

    /// An operating point with clean-separation numbers, parameterised only
    /// by target and recall — enough shape for the baseline gate.
    fn op(target_fpr: f64, recall: f64) -> OperatingPoint {
        OperatingPoint {
            target_fpr,
            threshold: 2.0,
            recall,
            false_positive_rate: 0.0,
            counts: Counts {
                true_positives: 80,
                false_negatives: 0,
                false_positives: 0,
                true_negatives: 132,
            },
            missed_attack_cases: vec![],
            false_positive_cases: vec![],
            by_family: vec![],
        }
    }

    fn baseline(json: &str) -> Baseline {
        parse_baseline(json).unwrap()
    }

    #[test]
    fn results_operating_point_without_a_floor_is_a_violation() {
        let b = baseline(
            r#"{ "schema_version": 1, "note": "n", "detector": "unicode-classes",
                  "operating_points": [ { "target_fpr": 0.0, "min_recall": 1.0 } ] }"#,
        );
        let violations = baseline_violations(&b, "unicode-classes", &[op(0.0, 1.0), op(0.01, 1.0)]);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("target_fpr=0.01"), "{violations:?}");
        assert!(
            violations[0].contains("no floor for this operating point"),
            "{violations:?}"
        );
    }

    #[test]
    fn every_results_operating_point_floored_and_met_passes() {
        let b = baseline(
            r#"{ "schema_version": 1, "note": "n", "detector": "unicode-classes",
                  "operating_points": [ { "target_fpr": 0.0, "min_recall": 1.0 },
                                        { "target_fpr": 0.01, "min_recall": 1.0 } ] }"#,
        );
        let violations = baseline_violations(&b, "unicode-classes", &[op(0.0, 1.0), op(0.01, 1.0)]);
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn an_unmet_floor_is_still_a_violation() {
        let b = baseline(
            r#"{ "schema_version": 1, "note": "n", "detector": "unicode-classes",
                  "operating_points": [ { "target_fpr": 0.0, "min_recall": 1.0 } ] }"#,
        );
        let violations = baseline_violations(&b, "unicode-classes", &[op(0.0, 0.5)]);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("min_recall=1"), "{violations:?}");
    }

    #[test]
    fn empty_baseline_operating_points_fail_to_load() {
        let err = parse_baseline(
            r#"{ "schema_version": 1, "note": "n", "detector": "d", "operating_points": [] }"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("no operating_points"), "{err}");
    }
}
