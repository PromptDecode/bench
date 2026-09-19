# The promptdecode corpus schema

This document is the normative specification of the `corpus/` directory. Corpus
authors and the benchmark runner both implement against it and against nothing
else: if a behaviour is not written here, it is not part of the contract. The
benchmark's headline measurement — recall at a stated false-positive rate — is
only defensible if every case is openly licensed, attributable, reviewable in a
diff, and processed deterministically. Every rule below serves one of those
four goals.

## Layout

```
corpus/
  SCHEMA.md            this document
  sources.json         the source registry: id -> attribution + licence
  cases/attack/*.json  one file per attack family
  cases/benign/*.json  one file per benign family
```

- The runner discovers family files by walking `corpus/cases/` recursively for
  `*.json`, sorted by path. There is no index and no manifest; the filesystem
  is the manifest.
- A case's label comes from the `label` field in its family file, never from
  the directory path. The `attack/` and `benign/` directories are a
  convenience for humans only; the runner must not read labels out of them.
- `SCHEMA.md` and `sources.json` live under `corpus/` but are not family
  files; they are never loaded as cases.
- All corpus files are UTF-8, without a byte order mark.

## Identifiers

"Kebab-case" throughout this document means lowercase letters and digits joined
by single hyphens, matching `^[a-z0-9]+(-[a-z0-9]+)*$`. No underscores, no
spaces, no uppercase.

## Family file schema

A family file is a single JSON object with exactly these fields:

- `family` (string, required): kebab-case identifier, unique across the
  corpus, and equal to the file stem — `plain-prose.json` must declare
  `"family": "plain-prose"`. The runner fails on a mismatch or on a duplicate
  family name.
- `label` (string, required): exactly `"attack"` or `"benign"` — lowercase,
  one of the two, nothing else. The label applies to every case in the file;
  a family is never mixed.
- `description` (string, required): one or two sentences on what this family
  is and why it belongs in the corpus.
- `cases` (array, required, non-empty): the cases, each matching the case
  schema below.

Skeleton:

```json
{
  "family": "example-family",
  "label": "attack",
  "description": "One or two sentences on what this family is and why it belongs in the corpus.",
  "cases": [
    {
      "id": "example-family-01",
      "title": "Short human-readable label",
      "text": "The case text, exactly as a detector would see it.",
      "rationale": "One sentence on why this text carries this label.",
      "source": { "id": "some-source-id", "locator": "optional pointer" }
    }
  ]
}
```

## Case schema

Each element of `cases`:

- `id` (string, required): kebab-case, globally unique across the whole
  corpus, attack and benign alike. The runner fails on duplicates.
  Convention: `<family>-<nn>`, as in `unicode-tag-block-07`.
- `title` (string, required): a short human-readable label, under 80
  characters.
- `text` (string, required): the case text exactly as a detector would see
  it; the runner feeds this string to the detector verbatim. Non-empty.
- `rationale` (string, required): one sentence on why this text carries this
  label. For benign cases that deliberately look suspicious, say what makes
  them legitimate.
- `source` (object, required): `{ "id": <string>, "locator": <string,
  optional> }`. `id` MUST match an `id` in `sources.json`; the runner fails if
  it does not. `locator` is an optional free-text pointer within that source —
  a page, a section heading, a URL fragment, a commit hash.

Every case therefore names its source and, through the source registry, its
licence. There is no family-level default and no implicit inheritance:
`source` is required on every single case, deliberately, so that no case can
lose its attribution when cases are moved between files.

## `sources.json`

The source registry maps source ids to attribution and licence:

```json
{
  "schema_version": 1,
  "sources": [
    {
      "id": "promptdecode-original",
      "name": "Authored for the promptdecode benchmark",
      "url": "https://github.com/PromptDecode/bench",
      "licence": "CC0-1.0",
      "licence_url": "https://creativecommons.org/publicdomain/zero/1.0/",
      "note": "Original text written for this corpus and dedicated to the public domain."
    }
  ]
}
```

Per source:

- `id` (string, required): kebab-case, unique within the file. This is the
  value that case `source.id` fields refer to.
- `name` (string, required): a human-readable description of where the text
  came from.
- `licence` (string, required): an SPDX licence identifier, such as `CC0-1.0`,
  `MIT`, or `CC-BY-4.0`. (The field name is spelled the British way,
  `licence`.)
- `licence_url` (string, required): a URL where the licence text can be read.
- `url` (string, optional): where the source itself can be found.
- `note` (string, optional): anything else a reviewer should know about
  provenance.

The top-level `schema_version` is an integer, currently `1`; bump it only for
breaking changes to this document. A case may only carry text that its
source's licence permits redistributing in this repository.

## The escaping rule

**Characters that are invisible or non-rendering MUST be written in the JSON
source as `\uXXXX` escapes, never as literal characters.** This is what makes
the corpus reviewable: a reviewer reading a diff must be able to see, in the
diff, exactly which invisible codepoint a case contains. A literal U+200B in a
diff looks like nothing at all; the six characters `​` look like what
they are.

The runner enforces this by reading the raw bytes of each family file before
parsing, and failing if any of these codepoints appear literally in the file
(as raw UTF-8 bytes, in any field):

- `U+00AD` — soft hyphen
- `U+061C` — Arabic letter mark
- `U+115F`, `U+1160` — Hangul fillers
- `U+180E` — Mongolian vowel separator
- `U+200B`–`U+200F` — zero-width space, zero-width non-joiner, zero-width
  joiner, left-to-right mark, right-to-left mark
- `U+202A`–`U+202E` — bidi embedding and override controls
- `U+2060`–`U+2064` — word joiner and invisible operators
- `U+2066`–`U+2069` — bidi isolates
- `U+3164` — Hangul filler
- `U+FE00`–`U+FE0F` — variation selectors
- `U+FEFF` — byte order mark / zero-width no-break space
- `U+FFA0` — halfwidth Hangul filler
- `U+E0000`–`U+E007F` — tag characters
- `U+E0100`–`U+E01EF` — variation selectors supplement
- `U+E000`–`U+F8FF`, `U+F0000`–`U+FFFFD`, `U+100000`–`U+10FFFD` — private use
  areas

Because `U+FEFF` is on the list, this also catches a byte order mark at the
start of a file.

Everything not on the list is fine to write literally, and visible non-ASCII
SHOULD be written literally: CJK, Arabic and Hebrew letters, Greek, Cyrillic,
accented Latin, emoji base characters, and mathematical alphanumerics are all
readable in a diff, and escaping them would make the corpus harder to review,
not easier. The line is drawn exactly where readability in a diff ends: if a
character renders as nothing, or renders as something its neighbouring
characters silently reinterpret, it goes in as an escape.

### Codepoints above U+FFFF: surrogate pairs

A `\uXXXX` escape holds four hex digits, so it can express codepoints only up
to `U+FFFF`. Codepoints above `U+FFFF` — including the tag characters — are
written as a UTF-16 surrogate pair: two consecutive `\uXXXX` escapes. For a
codepoint `C`:

```
high surrogate = 0xD800 + ((C - 0x10000) >> 10)
low  surrogate = 0xDC00 + ((C - 0x10000) & 0x3FF)
```

Worked example: `U+E0041`, the tag-block encoding of the letter `A`:

```
U+E0041 - U+10000 = 0xD0041
high = 0xD800 + (0xD0041 >> 10) = 0xDB40
low  = 0xDC00 + (0xD0041 & 0x3FF) = 0xDC41
```

So `U+E0041` is written in the JSON source as `"󠁁"`, and a JSON
parser combines the pair back into the single codepoint `U+E0041`. Tag-block
escapes have a memorable shorthand: the tag encoding of an ASCII character `X`
is `\udb40\udc` followed by the two hex digits of `X` — `a` (`U+0061`) is
`󠁡`, a space (`U+0020`) is `󠀠`.

Practical note for authors: Python's `json.dump(..., ensure_ascii=True)`
produces all of these escapes automatically. Tooling that emits raw UTF-8 by
default (serde_json, for instance) does not, so with such tooling the listed
codepoints must be escaped by hand — or, better, build the case text
programmatically from plain ASCII, as the `unicode-tag-block` exemplar file
does.

## Determinism

- Cases are processed in sorted order by `id`: a plain lexicographic sort of
  the id strings. This is the only ordering in the benchmark; within a family
  file, cases may be listed in any order.
- Zero-pad the numeric suffix of case ids to a fixed width within a family —
  `-01`, `-02`, ..., `-10` — so that lexicographic order and numeric order
  agree. (`-2` vs `-10` sorts wrong.)
- Nothing in the corpus may depend on wall-clock time, locale, or filesystem
  ordering. Family files must not rely on being read in directory-listing
  order, and case content must not assume a particular date, timezone, or
  locale of the machine evaluating it.

## Checklist for corpus authors

- One file per family at `corpus/cases/<label>/<family>.json`; `family` equals
  the file stem; `label` is exactly `"attack"` or `"benign"`.
- Every case has `id`, `title`, `text`, `rationale`, `source`; ids are
  globally unique and zero-padded; `source.id` exists in `sources.json`.
- No codepoint from the banned list appears literally anywhere in the file —
  escapes only, and surrogate pairs above `U+FFFF`.
- Visible non-ASCII is written literally.
- `text` is non-empty; `title` is under 80 characters; `rationale` is one
  sentence.
