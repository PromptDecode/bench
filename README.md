# promptdecode benchmark

The open benchmark: the corpus, the harness, and recall at a stated
false-positive rate.

[promptdeco.de](https://promptdeco.de) publishes no detection figures at all,
on purpose:

> We do not publish a percentage of attacks blocked. Published evasion rates
> against commercial detectors swing wildly with the technique used. A number
> that moves that much is not a number.

What replaces it is this: deterministic coverage of a named list of Unicode
classes, and recall at a stated false-positive rate on a named corpus, with
the corpus and the harness in the open.

## What this measures

Recall at a stated false-positive rate, on the corpus committed under
`corpus/`. Every case is scored. For each target false-positive rate, the
threshold is chosen first: the lowest score threshold whose false-positive
rate on benign cases stays within the target. Recall is then the share of
attack cases at or above that threshold.

The operating points are target false-positive rates of 0.0, 0.01 and 0.05.
At 0.0, no benign case reaches the threshold: an attack case counts only if
it outscores every benign case.

The numbers themselves live in `results.json`, because a number copied into
prose drifts out of date silently.

## Running it

```
cargo run -p promptdecode-bench
```

recomputes the entire benchmark from the committed corpus and writes
`results.json`. Flags:

- `--check` — CI mode. Writes nothing. Fails if the committed `results.json`
  no longer matches what the corpus produces, or if recall has dropped below
  the floor in `baseline.json`.
- `--explain <case-id>` — prints one case's score and its evidence breakdown,
  so any single number in `results.json` can be checked by hand.
- `--corpus <dir>`, `--out <file>`, `--baseline <file>` — point the harness
  at other locations.

`results.json` contains no timestamp and no absolute paths, deliberately: the
same corpus always produces byte-identical output, and CI can diff it.

## The corpus

[`corpus/SCHEMA.md`](corpus/SCHEMA.md) is the normative specification; this is
only the outline. Every case names its source, and the source resolves through
`corpus/sources.json` to a licence. The harness fails rather than scores a
case whose source does not resolve, so no case can be scored unattributed.

Invisible codepoints — zero-width characters, bidi controls, tag characters,
the rest — are written in the JSON source as `\uXXXX` escapes, never as
literal characters. A literal U+200B in a diff looks like nothing at all. The
escapes are what make a corpus diff reviewable by a human.

All current cases are original text written for this corpus and dedicated to
the public domain under CC0-1.0. The repository is separate from the engines
because third-party corpus text carries its own licensing, which is cleaner
kept out of the engine repositories.

## `results.json`

The schema is versioned (`schema_version`). The site renders the file without
transformation, so the field names and the nesting are a contract, not an
implementation detail.

`interpretation` is a fixed string, serialised immediately after
`schema_version`: a standing caveat carried in the file itself. It states
that the reference detector separates this corpus completely, and why that
is a fact about a corpus and a detector written in the same repository
rather than evidence that the detector generalises. The text is fixed so
that a site rendering the numbers cannot present them without it.

## What this does not cover

- **The corpus is small.** With N benign cases, the finest non-zero
  false-positive rate the corpus can express is 1/N. A target below that is
  not measurable here. The harness reports that resolution limit in
  `results.json` rather than hiding it.
- **No case is real traffic.** Every case is original text written for this
  corpus, not sampled from real prompts. This measures coverage of technique
  classes, not prevalence in the wild.
- **The corpus and the reference detector were authored in the same
  repository, by the same effort.** A detector evaluated on a corpus written
  alongside it is measuring its own coverage. The result is a reproducible
  statement about this corpus and this detector, and nothing wider.
- **The reference detector separates this corpus completely.** No attack
  case is missed and no benign case is flagged. That is a statement about
  the difficulty of the corpus, not the quality of the detector: a corpus
  written alongside a detector tends to contain the cases it was built to
  catch, and a benchmark its own reference implementation passes perfectly
  has no headroom left to measure anything with. The useful next step is
  adversarial cases this detector fails — those are what make the number
  mean something. Read the recall figure as a floor for regression
  detection, not as an effectiveness claim.
- **The coverage is Unicode-level smuggling and confusables.** It does not
  cover natural-language jailbreaks, multi-turn manipulation,
  retrieved-content injection, or any attack that is plain ASCII with no
  encoding trick.
- **Recall is per case, not weighted by severity.** A missed case and a
  missed class count the same.
- **No adversary adapts to it.** These are fixed cases. An attacker who reads
  this repository can construct text that evades every class listed.
- **The benign side is broad but not exhaustive.** Its language and script
  coverage is wide, and the false-positive rate generalises only as far as
  that coverage does.

A [Factory Zero](https://factory0.ventures) venture.
