//! The reference detector, `unicode-classes` v0.2.0.
//!
//! It scores text by summing evidence from thirteen independent
//! Unicode-class signals. Each signal has a **weight** (how much one
//! occurrence of that class indicates deliberate smuggling, chosen once from
//! first principles — see the weights table below — and never tuned
//! case-by-case against the corpus) and a **cap** (how many occurrences may
//! contribute, `contribution = weight * min(count, cap)`, so one pathological
//! case cannot dominate the corpus by repeating a character a thousand
//! times).
//!
//! # The weights table
//!
//! Weight rationale, per signal. The starting point prescribed for this
//! reference detector was: signals 1–3 at 4.0, signals 6/7/8/9/12 at 3.0,
//! everything else at 2.0, cap 3 throughout. These constants follow that
//! starting point exactly.
//!
//! | # | class                          | weight | reasoning |
//! |---|--------------------------------|--------|-----------|
//! | 1 | `tag-block`                     | 4.0 | tag characters have no typographic use whatsoever outside emoji flag sequences; a raw tag run is invisible-channel contraband, full stop |
//! | 2 | `private-use`                   | 4.0 | private-use codepoints render as nothing or as tofu for almost every reader; there is no legitimate reason for them in prose sent to an assistant |
//! | 3 | `unbalanced-bidi`               | 4.0 | an unterminated embedding/override or an unmatched isolate/terminator produces the visual-reordering (Trojan Source) attack; broken bidi state is never accidental typography |
//! | 4 | `bidi-control-without-rtl`      | 2.0 | a bidi control with no right-to-left text anywhere in the message has no possible rendering function, but the class overlaps heavily with 3, so it stays at the floor weight |
//! | 5 | `directional-mark-without-rtl`  | 2.0 | LRM/RLM/ALM without any RTL text are pure noise or payload; low weight because single stray marks are common editor accidents, not attacks |
//! | 6 | `zero-width-in-word`            | 3.0 | a zero-width character between two Latin letters is the classic keyword-splitting trick; between letters of cursive scripts or inside emoji the same characters are legitimate and excluded |
//! | 7 | `zero-width-run`                | 3.0 | three or more consecutive invisible codepoints is payload-shaped; no typographic convention chains invisibles like that |
//! | 8 | `variation-selector-anomaly`    | 3.0 | a variation selector must dress up a base character; one that follows nothing emoji-like, or stacks on another selector, is encoding games |
//! | 9 | `invisible-filler`              | 3.0 | Hangul fillers and the Mongolian vowel separator exist for jamo composition and Mongolian shaping; outside those scripts they only pad and align invisible payloads |
//! | 10 | `invisible-operator-outside-math` | 2.0 | invisible operators are meaningful only inside mathematics; with no math characters in sight they are either noise or payload, and their weight stays conservative because they alter nothing visually |
//! | 11 | `soft-hyphen-anomaly`           | 2.0 | a soft hyphen where no hyphenation point is plausible — a token of fewer than 6 letters — or denser than one break per three letters; justified typesetting puts a soft hyphen at *every* syllable boundary of a long compound, all inside one token, so density inside a long word is the legitimate shape and is excluded |
//! | 12 | `mixed-script-word`             | 3.0 | a **disguised word**: an otherwise-Latin word of 4+ letters in which a strict minority of the letters are look-alike Cyrillic/Greek/Armenian/Cherokee/Coptic substitutions; a two-letter Latin-Greek technical symbol (variable names, spectral lines, isotope notation) is not a word in disguise, and scripts mixing *between* words is normal multilingual text — both excluded |
//! | 13 | `fullwidth-latin-without-cjk`   | 2.0 | fullwidth Latin is normal inside CJK *script* text and visual spoofing outside it; fullwidth punctuation and the ideographic space cannot excuse it because they travel with the technique itself; math-alphanumeric tokens are the same trick in a fancier font |

use std::ops::Range;

use super::{Detector, Evidence, Verdict};

/// One signal's tuning.
struct SignalSpec {
    /// Stable class identifier surfaced in evidence and reports.
    class: &'static str,
    /// How much one occurrence indicates deliberate smuggling. Chosen from
    /// the principle stated in the module docs, never tuned against the
    /// corpus.
    weight: f64,
    /// At most this many occurrences contribute: `weight * min(count, cap)`.
    cap: usize,
}

/// The weights table: thirteen signals, in the order evidence is reported.
const SIGNALS: [SignalSpec; 13] = [
    SignalSpec {
        class: "tag-block",
        weight: 4.0,
        cap: 3,
    },
    SignalSpec {
        class: "private-use",
        weight: 4.0,
        cap: 3,
    },
    SignalSpec {
        class: "unbalanced-bidi",
        weight: 4.0,
        cap: 3,
    },
    SignalSpec {
        class: "bidi-control-without-rtl",
        weight: 2.0,
        cap: 3,
    },
    SignalSpec {
        class: "directional-mark-without-rtl",
        weight: 2.0,
        cap: 3,
    },
    SignalSpec {
        class: "zero-width-in-word",
        weight: 3.0,
        cap: 3,
    },
    SignalSpec {
        class: "zero-width-run",
        weight: 3.0,
        cap: 3,
    },
    SignalSpec {
        class: "variation-selector-anomaly",
        weight: 3.0,
        cap: 3,
    },
    SignalSpec {
        class: "invisible-filler",
        weight: 3.0,
        cap: 3,
    },
    SignalSpec {
        class: "invisible-operator-outside-math",
        weight: 2.0,
        cap: 3,
    },
    SignalSpec {
        class: "soft-hyphen-anomaly",
        weight: 2.0,
        cap: 3,
    },
    SignalSpec {
        class: "mixed-script-word",
        weight: 3.0,
        cap: 3,
    },
    SignalSpec {
        class: "fullwidth-latin-without-cjk",
        weight: 2.0,
        cap: 3,
    },
];

/// The reference Unicode-class detector.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnicodeClasses;

impl Detector for UnicodeClasses {
    fn id(&self) -> &str {
        "unicode-classes"
    }

    fn name(&self) -> &str {
        "Unicode character-class reference detector"
    }

    fn version(&self) -> &str {
        "0.2.0"
    }

    fn score(&self, text: &str) -> Verdict {
        let analysis = Analysis::new(text);
        let findings = [
            analysis.tag_block(),
            analysis.private_use(),
            analysis.unbalanced_bidi(),
            analysis.bidi_control_without_rtl(),
            analysis.directional_mark_without_rtl(),
            analysis.zero_width_in_word(),
            analysis.zero_width_run(),
            analysis.variation_selector_anomaly(),
            analysis.invisible_filler(),
            analysis.invisible_operator_outside_math(),
            analysis.soft_hyphen_anomaly(),
            analysis.mixed_script_word(),
            analysis.fullwidth_latin_without_cjk(),
        ];
        let mut score = 0.0;
        let mut evidence = Vec::new();
        for (spec, finding) in SIGNALS.iter().zip(findings) {
            if finding.count == 0 {
                continue;
            }
            let contribution = spec.weight * finding.count.min(spec.cap) as f64;
            score += contribution;
            evidence.push(Evidence {
                class: spec.class.to_string(),
                count: finding.count,
                contribution,
                note: finding.note,
            });
        }
        Verdict { score, evidence }
    }
}

/// What one signal observed.
struct Finding {
    count: usize,
    note: String,
}

impl Finding {
    fn none() -> Finding {
        Finding {
            count: 0,
            note: String::new(),
        }
    }

    fn new(count: usize, note: String) -> Finding {
        Finding { count, note }
    }
}

/// Precomputed facts about one text, shared by all signals. Built once per
/// score, from `text` alone — part of the purity contract.
struct Analysis {
    /// The text as a char vector; every index below is into this vector.
    chars: Vec<char>,
    /// Per-char flag: this position is a tag character (or cancel tag) inside
    /// a well-formed emoji tag sequence, which both the tag-block and
    /// zero-width-run signals must treat as legitimate.
    tag_exempt: Vec<bool>,
    /// Does the text contain any right-to-left letter?
    has_rtl: bool,
    /// Does the text contain any CJK *script* character (ideographs, kana,
    /// Hangul)? Deliberately not: CJK punctuation, the ideographic space, or
    /// fullwidth forms — see [`CJK_SCRIPT_RANGES`].
    has_cjk_script: bool,
    /// Does the text contain any mathematical character?
    has_math: bool,
    /// Maximal runs of alphanumeric characters ("tokens" for word-level
    /// signals): split on whitespace, punctuation, and symbols.
    tokens_alnum: Vec<Range<usize>>,
    /// Same, but soft hyphens stay inside the token, because hyphenation is
    /// exactly what a soft hyphen means.
    tokens_word: Vec<Range<usize>>,
}

impl Analysis {
    fn new(text: &str) -> Analysis {
        let chars: Vec<char> = text.chars().collect();
        let tag_exempt = well_formed_tag_spans(&chars);
        let mut has_rtl = false;
        let mut has_cjk_script = false;
        let mut has_math = false;
        for &c in &chars {
            has_rtl |= in_ranges(c, RTL_RANGES);
            has_cjk_script |= in_ranges(c, CJK_SCRIPT_RANGES);
            has_math |= in_ranges(c, MATH_RANGES);
        }
        let tokens_alnum = tokens(&chars, false);
        let tokens_word = tokens(&chars, true);
        Analysis {
            chars,
            tag_exempt,
            has_rtl,
            has_cjk_script,
            has_math,
            tokens_alnum,
            tokens_word,
        }
    }

    /// Signal 1. Counts tag characters (U+E0000–U+E007F) that are NOT part of
    /// a well-formed emoji tag sequence (base U+1F3F4, one or more tag chars
    /// U+E0020–U+E007E, cancel tag U+E007F). Subdivision-flag emoji like the
    /// Scotland flag are exactly the excluded, legitimate use.
    fn tag_block(&self) -> Finding {
        let mut count = 0usize;
        let mut decoded = String::new();
        for (i, &c) in self.chars.iter().enumerate() {
            if !in_ranges(c, TAG_RANGES) || self.tag_exempt[i] {
                continue;
            }
            count += 1;
            let v = c as u32;
            if (0xE0020..=0xE007E).contains(&v) {
                if let Some(ascii) = char::from_u32(v - 0xE0000) {
                    decoded.push(ascii);
                }
            }
        }
        if count == 0 {
            return Finding::none();
        }
        Finding::new(
            count,
            format!(
                "tag characters outside well-formed emoji flag sequences (payload decodes to: \"{}\")",
                elide(&decoded, 64)
            ),
        )
    }

    /// Signal 2. Any private-use codepoint: U+E000–U+F8FF, U+F0000–U+FFFFD,
    /// U+100000–U+10FFFD. There is no legitimate-use exclusion because there
    /// is no legitimate use in prose: PUA only renders for readers with the
    /// right private font, which is precisely why smugglers like it.
    fn private_use(&self) -> Finding {
        let count = self
            .chars
            .iter()
            .filter(|&&c| in_ranges(c, PUA_RANGES))
            .count();
        if count == 0 {
            return Finding::none();
        }
        Finding::new(
            count,
            "private-use codepoints, which render only with a private font and are invisible channel elsewhere".to_string(),
        )
    }

    /// Signal 3. Bidi state-machine violations: unterminated
    /// embedding/override initiators (U+202A–U+202E need U+202C), unmatched
    /// isolate initiators (U+2066–U+2068 need U+2069), and stray terminators.
    /// Balanced, properly nested bidi contributes nothing — that is the
    /// legitimate use (quoting RTL prose) that this signal deliberately
    /// excludes.
    fn unbalanced_bidi(&self) -> Finding {
        let mut open_embeddings = 0usize;
        let mut open_isolates = 0usize;
        let mut stray_terminators = 0usize;
        for &c in &self.chars {
            match c {
                // U+202A LRE, U+202B RLE, U+202D LRO, U+202E RLO initiate;
                // U+202C (PDF) terminates and is handled below.
                '\u{202A}' | '\u{202B}' | '\u{202D}' | '\u{202E}' => open_embeddings += 1,
                '\u{202C}' => {
                    if open_embeddings > 0 {
                        open_embeddings -= 1;
                    } else {
                        stray_terminators += 1;
                    }
                }
                '\u{2066}'..='\u{2068}' => open_isolates += 1,
                '\u{2069}' => {
                    if open_isolates > 0 {
                        open_isolates -= 1;
                    } else {
                        stray_terminators += 1;
                    }
                }
                _ => {}
            }
        }
        let count = open_embeddings + open_isolates + stray_terminators;
        if count == 0 {
            return Finding::none();
        }
        Finding::new(
            count,
            format!(
                "broken bidi state: {open_embeddings} unterminated embedding/override initiator(s), {open_isolates} unmatched isolate initiator(s), {stray_terminators} stray terminator(s)"
            ),
        )
    }

    /// Signal 4. Any bidi embedding/override/isolate control in a text that
    /// contains no right-to-left letters at all (Hebrew, Arabic, Syriac,
    /// Thaana, NKo and Arabic presentation forms). A bidi control whose
    /// effect has nothing to act on exists only to confuse parsers or hide
    /// content direction; around genuine RTL text it is legitimate and does
    /// not fire.
    fn bidi_control_without_rtl(&self) -> Finding {
        if self.has_rtl {
            return Finding::none();
        }
        let count = self
            .chars
            .iter()
            .filter(|&&c| in_ranges(c, BIDI_CONTROL_RANGES))
            .count();
        if count == 0 {
            return Finding::none();
        }
        Finding::new(
            count,
            "bidi controls present but the text contains no right-to-left letters for them to govern".to_string(),
        )
    }

    /// Signal 5. Directional marks (U+200E LRM, U+200F RLM, U+061C ALM) in a
    /// text with no RTL letters. Same reasoning as signal 4, one level
    /// weaker: a single stray LRM is a common editor accident, not an attack.
    fn directional_mark_without_rtl(&self) -> Finding {
        if self.has_rtl {
            return Finding::none();
        }
        let count = self
            .chars
            .iter()
            .filter(|&&c| matches!(c, '\u{200E}' | '\u{200F}' | '\u{061C}'))
            .count();
        if count == 0 {
            return Finding::none();
        }
        Finding::new(
            count,
            "directional marks (LRM/RLM/ALM) present but the text contains no right-to-left letters".to_string(),
        )
    }

    /// Signal 6. A zero-width character (U+200B, U+200C, U+200D, U+2060,
    /// U+FEFF) sitting **between two Latin letters**. That is keyword
    /// splitting ("free\u{200B}beats") with no typographic excuse. It
    /// deliberately excludes joiners between two letters of the same
    /// non-Latin cursive script (Persian ZWNJ, Devanagari, Bengali, Tamil),
    /// which are required orthography, and ZWJ between emoji, which builds
    /// compound emoji.
    fn zero_width_in_word(&self) -> Finding {
        let mut count = 0usize;
        let mut seen: Vec<char> = Vec::new();
        for (i, &c) in self.chars.iter().enumerate() {
            if !in_ranges(c, ZERO_WIDTH_RANGES) || i == 0 || i + 1 >= self.chars.len() {
                continue;
            }
            if is_latin_letter(self.chars[i - 1]) && is_latin_letter(self.chars[i + 1]) {
                count += 1;
                if !seen.contains(&c) {
                    seen.push(c);
                }
            }
        }
        if count == 0 {
            return Finding::none();
        }
        let names: Vec<String> = seen
            .iter()
            .map(|c| format!("U+{:04X}", *c as u32))
            .collect();
        Finding::new(
            count,
            format!(
                "zero-width character(s) between two Latin letters ({}) — keyword splitting with no typographic purpose",
                names.join(", ")
            ),
        )
    }

    /// Signal 7. Runs of 3+ consecutive invisible codepoints — zero-width
    /// spaces/joiners, bidi controls, variation selectors, tag characters,
    /// soft hyphens, fillers. Payload-shaped, not typographic. Tag characters
    /// inside a well-formed emoji flag sequence are excluded (they render as
    /// a flag), and isolated single or double invisibles are left to the
    /// more specific signals above.
    fn zero_width_run(&self) -> Finding {
        let mut count = 0usize;
        let mut longest = 0usize;
        let mut run = 0usize;
        for (i, &c) in self.chars.iter().enumerate() {
            let invisible = in_ranges(c, INVISIBLE_RUN_RANGES) && !self.tag_exempt[i];
            if invisible {
                run += 1;
            } else if run > 0 {
                if run >= 3 {
                    count += run;
                    longest = longest.max(run);
                }
                run = 0;
            }
        }
        if run >= 3 {
            count += run;
            longest = longest.max(run);
        }
        if count == 0 {
            return Finding::none();
        }
        Finding::new(
            count,
            format!(
                "{count} invisible codepoint(s) in run(s) of 3 or more (longest run {longest})"
            ),
        )
    }

    /// Signal 8. Variation selectors (U+FE00–U+FE0F, U+E0100–U+E01EF) that do
    /// not immediately follow an emoji or symbol base character, or runs of
    /// 2+ consecutive selectors. A single VS16/VS15 after an emoji base is
    /// the legitimate, excluded use: it only picks colour vs. mono rendering.
    fn variation_selector_anomaly(&self) -> Finding {
        let mut count = 0usize;
        for (i, &c) in self.chars.iter().enumerate() {
            if !in_ranges(c, VARIATION_SELECTOR_RANGES) {
                continue;
            }
            let after_base = i > 0 && is_emoji_or_symbol_base(self.chars[i - 1]);
            let stacked = i > 0 && in_ranges(self.chars[i - 1], VARIATION_SELECTOR_RANGES);
            if !after_base || stacked {
                count += 1;
            }
        }
        if count == 0 {
            return Finding::none();
        }
        Finding::new(
            count,
            "variation selector(s) with no emoji/symbol base character, or stacked on another variation selector".to_string(),
        )
    }

    /// Signal 9. Invisible filler codepoints: U+115F, U+1160 (Hangul
    /// cho/jung fillers), U+3164, U+FFA0 (Hangul filler), U+180E (Mongolian
    /// vowel separator). Inside Hangul jamo composition or Mongolian shaping
    /// they are orthography; outside those scripts, which is the only thing
    /// this signal sees them as, they exist to pad and align payloads.
    fn invisible_filler(&self) -> Finding {
        let count = self
            .chars
            .iter()
            .filter(|&&c| {
                matches!(
                    c,
                    '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}' | '\u{180E}'
                )
            })
            .count();
        if count == 0 {
            return Finding::none();
        }
        Finding::new(
            count,
            "invisible filler codepoints (Hangul fillers / Mongolian vowel separator) with no Hangul or Mongolian text to compose".to_string(),
        )
    }

    /// Signal 10. Invisible operators (U+2061–U+2064: function application,
    /// invisible times, comma, plus) in a text containing no other
    /// mathematical characters (Greek letters, math operators, superscripts/
    /// subscripts, etc.). Inside math markup they are legitimate and the
    /// absence-check excludes them; outside math they are an invisible
    /// channel that survives most normalisation.
    fn invisible_operator_outside_math(&self) -> Finding {
        if self.has_math {
            return Finding::none();
        }
        let count = self
            .chars
            .iter()
            .filter(|&&c| (0x2061..=0x2064).contains(&(c as u32)))
            .count();
        if count == 0 {
            return Finding::none();
        }
        Finding::new(
            count,
            "invisible operator(s) (U+2061-U+2064) in text with no mathematical characters"
                .to_string(),
        )
    }

    /// Signal 11. A soft hyphen (U+00AD) where no hyphenation point is
    /// plausible, or at a density no syllabification would produce. A soft
    /// hyphen marks a syllable boundary that a renderer may break at, so
    /// legitimate justified typesetting puts one at *every* syllable boundary
    /// of a long compound — which all sit inside one token by construction —
    /// and real syllabification never yields more than roughly one break per
    /// three letters. That gives two clauses. A token of fewer than 6 letters
    /// has no room for a hyphenation point at all, so a soft hyphen there can
    /// only be keyword obfuscation ("ga\u{00AD}za" renders as "ga-za" but
    /// normalises to "gaza"). And a token carrying more soft hyphens than
    /// `letters / 3` is denser than any real hyphenation, so the extras are
    /// padding a keyword-splitting payload. Dense hyphenation of a genuinely
    /// long compound — the fully legitimate shape — fails both clauses and
    /// stays silent.
    fn soft_hyphen_anomaly(&self) -> Finding {
        let mut count = 0usize;
        let mut example = String::new();
        for token in &self.tokens_word {
            let slice = &self.chars[token.clone()];
            let shy_positions = slice.iter().filter(|&&c| c == '\u{00AD}').count();
            if shy_positions == 0 {
                continue;
            }
            let letters = slice.iter().filter(|&&c| c.is_alphabetic()).count();
            if letters < 6 || shy_positions > letters / 3 {
                count += shy_positions;
                if example.is_empty() {
                    example = slice.iter().collect::<String>();
                }
            }
        }
        if count == 0 {
            return Finding::none();
        }
        Finding::new(
            count,
            format!(
                "soft hyphen(s) in a token of fewer than 6 letters, or denser than one hyphenation point per three letters (e.g. \"{example}\")"
            ),
        )
    }

    /// Signal 12. A **disguised word**: a single token (run of letters, split
    /// on whitespace and punctuation) that reads as a Latin word but has had
    /// a strict minority of its letters swapped for look-alike letters from
    /// Cyrillic, Greek, Armenian, Cherokee, or Coptic ("p\u{0430}ypal" with a
    /// Cyrillic а). That is the shape a homoglyph attack must take: it works
    /// by impersonating a word a reader recognises, so the token has to be a
    /// word (at least 4 letters) and the substitution has to stay a minority
    /// of its letters, or the disguise no longer reads as the word. Both
    /// gates therefore also mark the legitimate uses this signal must not
    /// flag: a short Latin-Greek pair is a technical symbol, not a disguised
    /// word — the Greek letter is doing its own job, in plain sight, whether
    /// as a variable name, a spectral line, or isotope notation — and
    /// legitimate multilingual text mixes scripts *between* words, so a
    /// Cyrillic sentence quoting a Latin word fires nothing.
    fn mixed_script_word(&self) -> Finding {
        let mut count = 0usize;
        let mut example = String::new();
        for token in &self.tokens_alnum {
            let slice = &self.chars[token.clone()];
            let mut letters = 0usize;
            let mut substituted = 0usize;
            for &c in slice {
                if !c.is_alphabetic() {
                    continue;
                }
                letters += 1;
                if !is_latin_letter(c) && spoofing_script_of(c).is_some() {
                    substituted += 1;
                }
            }
            // A word (not a two-letter symbol), and the substitutions are a
            // strict minority of its letters (fewer than half) — the shape of
            // a word disguised by look-alike swaps, not a symbol or a word
            // written in another script.
            if letters >= 4 && substituted > 0 && substituted * 2 < letters {
                count += 1;
                if example.is_empty() {
                    example = slice.iter().collect();
                }
            }
        }
        if count == 0 {
            return Finding::none();
        }
        Finding::new(
            count,
            format!(
                "token(s) reading as Latin words with a strict minority of letters substituted from Cyrillic/Greek/Armenian/Cherokee/Coptic (e.g. \"{example}\") — homoglyph spoofing shape"
            ),
        )
    }

    /// Signal 13. Fullwidth Latin letters (U+FF21–U+FF3A, U+FF41–U+FF5A) in a
    /// text containing no CJK *script* characters — where they have no
    /// typographic purpose and only fake or disguise Latin words — plus tokens
    /// made predominantly of mathematical alphanumeric symbols
    /// (U+1D400–U+1D7FF) or enclosed alphanumerics. Inside genuine CJK
    /// writing (ideographs, kana, Hangul) fullwidth Latin is the normal way
    /// to set Latin words and is excluded. The gate counts script characters
    /// only ([`CJK_SCRIPT_RANGES`]): fullwidth punctuation, the ideographic
    /// space, and the fullwidth forms block travel with fullwidth Latin
    /// inside the technique itself, so they cannot serve as the evidence that
    /// excuses it.
    fn fullwidth_latin_without_cjk(&self) -> Finding {
        let mut count = 0usize;
        let mut fullwidth = 0usize;
        let mut math_tokens = 0usize;
        if !self.has_cjk_script {
            fullwidth = self
                .chars
                .iter()
                .filter(|&&c| in_ranges(c, FULLWIDTH_LATIN_RANGES))
                .count();
            count += fullwidth;
        }
        for token in &self.tokens_alnum {
            let slice = &self.chars[token.clone()];
            let letters: Vec<char> = slice
                .iter()
                .copied()
                .filter(|c| c.is_alphabetic())
                .collect();
            if letters.len() < 2 {
                continue;
            }
            let styled = letters
                .iter()
                .filter(|&&c| {
                    in_ranges(c, MATH_ALPHANUMERIC_RANGES) || in_ranges(c, ENCLOSED_RANGES)
                })
                .count();
            if styled * 2 > letters.len() {
                math_tokens += 1;
                count += 1;
            }
        }
        if count == 0 {
            return Finding::none();
        }
        let mut note = String::new();
        if fullwidth > 0 {
            note.push_str(&format!(
                "{fullwidth} fullwidth Latin letter(s) but no CJK script characters (ideographs, kana, Hangul) anywhere in the text"
            ));
        }
        if math_tokens > 0 {
            if !note.is_empty() {
                note.push_str("; ");
            }
            note.push_str(&format!(
                "{math_tokens} token(s) made predominantly of mathematical alphanumeric or enclosed symbols"
            ));
        }
        Finding::new(count, note)
    }
}

/// Character-range tables. Inclusive (lo, hi) pairs.
const RTL_RANGES: &[(u32, u32)] = &[
    (0x0590, 0x05FF), // Hebrew
    (0x0600, 0x06FF), // Arabic
    (0x0700, 0x074F), // Syriac
    (0x0750, 0x077F), // Arabic supplement
    (0x0780, 0x07BF), // Thaana
    (0x07C0, 0x07FF), // NKo
    (0xFB50, 0xFDFF), // Arabic presentation forms A
    (0xFE70, 0xFEFF), // Arabic presentation forms B
];

const BIDI_CONTROL_RANGES: &[(u32, u32)] = &[
    (0x202A, 0x202E), // LRE LRO RLE RLO PDF
    (0x2066, 0x2069), // LRI RLI FSI PDI
];

const ZERO_WIDTH_RANGES: &[(u32, u32)] = &[
    (0x200B, 0x200D), // ZWSP ZWNJ ZWJ
    (0x2060, 0x2060), // word joiner
    (0xFEFF, 0xFEFF), // zero-width no-break space
];

const TAG_RANGES: &[(u32, u32)] = &[(0xE0000, 0xE007F)];

const PUA_RANGES: &[(u32, u32)] = &[(0xE000, 0xF8FF), (0xF0000, 0xFFFFD), (0x100000, 0x10FFFD)];

const VARIATION_SELECTOR_RANGES: &[(u32, u32)] = &[(0xFE00, 0xFE0F), (0xE0100, 0xE01EF)];

/// The set counted by the zero-width-run signal: everything invisible in
/// prose, including bidi controls and selectors but excluding private use
/// (which has its own signal and often renders in icon fonts).
const INVISIBLE_RUN_RANGES: &[(u32, u32)] = &[
    (0x00AD, 0x00AD),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x2069),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xE0000, 0xE007F),
    (0xE0100, 0xE01EF),
];

/// Greek and Coptic block (incl. Greek Extended), superscripts/subscripts,
/// mathematical operators, miscellaneous mathematical symbols A, and
/// supplemental mathematical operators.
const MATH_RANGES: &[(u32, u32)] = &[
    (0x0370, 0x03FF),
    (0x1F00, 0x1FFF),
    (0x00B2, 0x00B3),
    (0x00B9, 0x00B9),
    (0x2070, 0x209F),
    (0x2200, 0x22FF),
    (0x27C0, 0x27EF),
    (0x2A00, 0x2AFF),
];

/// CJK *script* characters only: the gate signal 13 uses to decide that
/// fullwidth Latin is legitimate. Deliberately script-only, because the
/// evidence that excuses a technique must be independent of the technique:
/// the ideographic space U+3000, CJK punctuation, and the fullwidth forms
/// block all travel *with* fullwidth Latin inside the obfuscation technique
/// itself (an attacker dressing Latin words in fullwidth styling emits
/// fullwidth spaces and fullwidth punctuation alongside them), so a single
/// fullwidth space must not be able to legitimise a whole run of fullwidth
/// Latin. Only actual ideographs, kana, and Hangul show that the text
/// genuinely lives in a CJK typographic context where fullwidth Latin is the
/// normal way to set Latin words.
const CJK_SCRIPT_RANGES: &[(u32, u32)] = &[
    (0x1100, 0x11FF), // Hangul Jamo
    (0x3040, 0x309F), // Hiragana
    (0x30A0, 0x30FF), // Katakana
    (0x3400, 0x4DBF), // CJK Unified Ideographs Extension A
    (0x4E00, 0x9FFF), // CJK Unified Ideographs
    (0xAC00, 0xD7AF), // Hangul syllables
];

const FULLWIDTH_LATIN_RANGES: &[(u32, u32)] = &[(0xFF21, 0xFF3A), (0xFF41, 0xFF5A)];

const MATH_ALPHANUMERIC_RANGES: &[(u32, u32)] = &[(0x1D400, 0x1D7FF)];

const ENCLOSED_RANGES: &[(u32, u32)] = &[(0x2460, 0x24FF), (0x1F100, 0x1F1FF)];

fn in_ranges(c: char, ranges: &[(u32, u32)]) -> bool {
    let v = c as u32;
    ranges.iter().any(|&(lo, hi)| v >= lo && v <= hi)
}

/// Latin letters: ASCII plus the accented Latin ranges that render as the
/// same alphabet to a reader. Cyrillic "а" must not count as Latin here —
/// that confusion is exactly what signal 12 exists to catch.
fn is_latin_letter(c: char) -> bool {
    let v = c as u32;
    c.is_ascii_alphabetic()
        || (0x00C0..=0x00D6).contains(&v)
        || (0x00D8..=0x00F6).contains(&v)
        || (0x00F8..=0x02C1).contains(&v)
        || (0x1E00..=0x1EFF).contains(&v)
}

/// The scripts signal 12 flags when found sharing a token with Latin.
fn spoofing_script_of(c: char) -> Option<&'static str> {
    let v = c as u32;
    let script = if (0x0400..=0x052F).contains(&v) {
        "Cyrillic"
    } else if (0x0370..=0x03FF).contains(&v) || (0x1F00..=0x1FFF).contains(&v) {
        "Greek"
    } else if (0x0530..=0x058F).contains(&v) {
        "Armenian"
    } else if (0x13A0..=0x13FF).contains(&v) || (0xAB70..=0xABFF).contains(&v) {
        "Cherokee"
    } else if (0x2C80..=0x2CFF).contains(&v) {
        "Coptic"
    } else {
        return None;
    };
    Some(script)
}

/// Emoji and symbol base characters that a variation selector may
/// legitimately follow: misc symbols, dingbats, arrows, misc technical,
/// geometric shapes, enclosed alphanumerics used as emoji bases, keycap
/// bases (digits, #, *), and the supplementary emoji planes.
fn is_emoji_or_symbol_base(c: char) -> bool {
    let v = c as u32;
    c == '\u{00A9}'
        || c == '\u{00AE}'
        || c == '\u{0023}'
        || c == '\u{002A}'
        || (0x0030..=0x0039).contains(&v)
        || (0x203C..=0x203C).contains(&v)
        || (0x2049..=0x2049).contains(&v)
        || (0x2122..=0x2122).contains(&v)
        || (0x2139..=0x2139).contains(&v)
        || (0x2194..=0x21FF).contains(&v)
        || (0x2300..=0x23FF).contains(&v)
        || (0x24C2..=0x24C2).contains(&v)
        || (0x25A0..=0x25FF).contains(&v)
        || (0x2600..=0x27BF).contains(&v)
        || (0x2934..=0x2935).contains(&v)
        || (0x2B00..=0x2BFF).contains(&v)
        || (0x3030..=0x3030).contains(&v)
        || (0x303D..=0x303D).contains(&v)
        || (0x3297..=0x3297).contains(&v)
        || (0x3299..=0x3299).contains(&v)
        || (0x1F000..=0x1FAFF).contains(&v)
        || (0x1FB00..=0x1FBFF).contains(&v)
}

/// Finds well-formed emoji tag sequences — base U+1F3F4, one or more tag
/// characters U+E0020–U+E007E, cancel tag U+E007F — and returns a per-char
/// exemption mask over the sequence's tag characters and cancel tag. Those
/// codepoints render as a subdivision flag (Scotland, England, Texas...),
/// which is the legitimate use the tag-block signal must not punish.
fn well_formed_tag_spans(chars: &[char]) -> Vec<bool> {
    let mut exempt = vec![false; chars.len()];
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] == '\u{1F3F4}' {
            let mut j = i + 1;
            while j < chars.len() && (0xE0020..=0xE007E).contains(&(chars[j] as u32)) {
                j += 1;
            }
            if j > i + 1 && j < chars.len() && chars[j] == '\u{E007F}' {
                for slot in exempt[i + 1..=j].iter_mut() {
                    *slot = true;
                }
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    exempt
}

/// Maximal token ranges: runs of alphanumeric characters (plus, when
/// `keep_soft_hyphen`, soft hyphens, because hyphenation points live inside
/// words). Whitespace, punctuation, and symbols all break tokens.
fn tokens(chars: &[char], keep_soft_hyphen: bool) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for (i, &c) in chars.iter().enumerate() {
        let in_token = c.is_alphanumeric() || (keep_soft_hyphen && c == '\u{00AD}');
        if in_token && start.is_none() {
            start = Some(i);
        }
        if !in_token {
            if let Some(s) = start.take() {
                out.push(s..i);
            }
        }
    }
    if let Some(s) = start {
        out.push(s..chars.len());
    }
    out
}

/// Truncates a decoded payload for a note, so a pathological case cannot
/// produce an absurd evidence line.
fn elide(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let prefix: String = s.chars().take(max_chars).collect();
        format!("{prefix}...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score(text: &str) -> Verdict {
        UnicodeClasses.score(text)
    }

    fn total(text: &str) -> f64 {
        score(text).score
    }

    fn class_count(text: &str, class: &str) -> Option<(usize, f64)> {
        score(text)
            .evidence
            .iter()
            .find(|e| e.class == class)
            .map(|e| (e.count, e.contribution))
    }

    fn fires(text: &str, class: &str) -> bool {
        class_count(text, class).is_some()
    }

    // ------------------------------------------------------------------
    // Per-signal: must fire.
    // ------------------------------------------------------------------

    #[test]
    fn fires_tag_block_on_raw_tag_run() {
        let text = "hello \u{E0041}\u{E0042}\u{E0043} world";
        let (count, contribution) = class_count(text, "tag-block").expect("should fire");
        assert_eq!(count, 3);
        assert_eq!(contribution, 12.0); // 4.0 * min(3, cap 3)
        assert!(total(text) >= 12.0);
    }

    #[test]
    fn fires_private_use() {
        let (count, contribution) =
            class_count("a \u{E000} b \u{F8FF}", "private-use").expect("should fire");
        assert_eq!(count, 2);
        assert_eq!(contribution, 8.0);
    }

    #[test]
    fn fires_unbalanced_bidi_on_unterminated_override() {
        let (_, contribution) =
            class_count("abc \u{202E} def", "unbalanced-bidi").expect("should fire");
        assert_eq!(contribution, 4.0);
    }

    #[test]
    fn fires_unbalanced_bidi_on_stray_terminator() {
        let (count, _) =
            class_count("\u{202C} nothing to close", "unbalanced-bidi").expect("should fire");
        assert_eq!(count, 1);
    }

    #[test]
    fn fires_bidi_control_without_rtl() {
        // Balanced embedding (signal 3 silent) but no RTL letters anywhere.
        let text = "\u{202A}ordered text\u{202C}";
        assert!(!fires(text, "unbalanced-bidi"));
        let (count, contribution) =
            class_count(text, "bidi-control-without-rtl").expect("should fire");
        assert_eq!(count, 2);
        assert_eq!(contribution, 4.0); // 2.0 * min(2, 3)
    }

    #[test]
    fn fires_directional_mark_without_rtl() {
        let (count, contribution) =
            class_count("a\u{200E}b", "directional-mark-without-rtl").expect("should fire");
        assert_eq!(count, 1);
        assert_eq!(contribution, 2.0);
    }

    #[test]
    fn fires_zero_width_in_word() {
        let (count, contribution) =
            class_count("abo\u{200C}ut", "zero-width-in-word").expect("should fire");
        assert_eq!(count, 1);
        assert_eq!(contribution, 3.0);
    }

    #[test]
    fn fires_zero_width_run() {
        let (count, contribution) =
            class_count("a\u{200B}\u{200C}\u{2060}b", "zero-width-run").expect("should fire");
        assert_eq!(count, 3);
        assert_eq!(contribution, 9.0);
    }

    #[test]
    fn fires_variation_selector_anomaly_on_selector_without_base() {
        let (count, contribution) =
            class_count("pla\u{FE0F}in", "variation-selector-anomaly").expect("should fire");
        assert_eq!(count, 1);
        assert_eq!(contribution, 3.0);
    }

    #[test]
    fn fires_variation_selector_anomaly_on_stacked_selectors() {
        // Both follow an emoji base, but the second stacks on the first.
        let (count, _) = class_count("\u{1F600}\u{FE0F}\u{FE0E}", "variation-selector-anomaly")
            .expect("should fire");
        assert_eq!(count, 1);
    }

    #[test]
    fn fires_invisible_filler() {
        let (count, contribution) =
            class_count("a\u{3164}b\u{1160}c", "invisible-filler").expect("should fire");
        assert_eq!(count, 2);
        assert_eq!(contribution, 6.0);
    }

    #[test]
    fn fires_invisible_operator_outside_math() {
        let (count, contribution) =
            class_count("x\u{2062}y", "invisible-operator-outside-math").expect("should fire");
        assert_eq!(count, 1);
        assert_eq!(contribution, 2.0);
    }

    #[test]
    fn fires_soft_hyphen_in_short_token() {
        let (count, contribution) =
            class_count("ga\u{00AD}za strip", "soft-hyphen-anomaly").expect("should fire");
        assert_eq!(count, 1);
        assert_eq!(contribution, 2.0);
    }

    #[test]
    fn fires_soft_hyphen_when_denser_than_one_break_per_three_letters() {
        // 7 letters with 3 soft hyphens: 3 > 7/3, denser than any real
        // syllabification would place.
        let (count, _) = class_count("ab\u{00AD}cd\u{00AD}ef\u{00AD}g", "soft-hyphen-anomaly")
            .expect("should fire");
        assert_eq!(count, 3);
    }

    #[test]
    fn fires_mixed_script_word_on_minority_substitution() {
        // 4 letters, one of them a Cyrillic а: a disguised word.
        let (count, contribution) =
            class_count("xy\u{0430}z", "mixed-script-word").expect("should fire");
        assert_eq!(count, 1);
        assert_eq!(contribution, 3.0);
    }

    #[test]
    fn fires_mixed_script_word_cyrillic_greek_pair() {
        // 5 letters with 2 substitutions from different scripts: still a
        // strict minority.
        assert!(fires("abc\u{0430}\u{03B1}", "mixed-script-word"));
    }

    #[test]
    fn mixed_script_two_letter_technical_symbol_does_not_fire() {
        // A Latin letter paired with a Greek letter is a technical symbol
        // (variable, spectral line, isotope), not a disguised word: too few
        // letters for the disguise to read as a word.
        for token in ["H\u{03B1}", "x\u{03B2}"] {
            assert_eq!(class_count(token, "mixed-script-word"), None, "{token}");
        }
    }

    #[test]
    fn mixed_script_word_with_majority_substitution_does_not_fire() {
        // Substitutions at exactly half the letters: not a strict minority,
        // so the token no longer reads as a Latin word and the signal stays
        // silent.
        assert_eq!(class_count("ab\u{0430}\u{03B1}", "mixed-script-word"), None);
    }

    #[test]
    fn fires_fullwidth_latin_without_cjk() {
        let (count, contribution) =
            class_count("\u{FF21}\u{FF22}\u{FF43}", "fullwidth-latin-without-cjk")
                .expect("should fire");
        assert_eq!(count, 3);
        assert_eq!(contribution, 6.0); // 2.0 * min(3, 3)
    }

    #[test]
    fn fires_math_alphanumeric_token() {
        let text = "\u{1D538}\u{1D539}\u{1D53A}";
        let (count, _) = class_count(text, "fullwidth-latin-without-cjk").expect("should fire");
        assert_eq!(count, 1); // one token, not three letters
    }

    // ------------------------------------------------------------------
    // Per-signal: must NOT fire on legitimate usage.
    // ------------------------------------------------------------------

    #[test]
    fn scotland_flag_scores_zero_from_tag_block() {
        // U+1F3F4 + gb sct tags + cancel: the well-formed subdivision flag.
        let flag = "\u{1F3F4}\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E007F}";
        assert_eq!(class_count(flag, "tag-block"), None);
        // And nothing else fires either: the flag is fully legitimate.
        assert_eq!(total(flag), 0.0, "evidence: {:?}", score(flag).evidence);
    }

    #[test]
    fn england_flag_and_flags_adjacent_to_text_score_zero() {
        let text = "Paid leave debated in Edinburgh today \u{1F3F4}\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}.";
        assert_eq!(total(text), 0.0, "evidence: {:?}", score(text).evidence);
    }

    #[test]
    fn malformed_flag_sequence_still_fires_tag_block() {
        // Tags after the flag base but without the cancel tag: not a
        // well-formed sequence, so it counts.
        let text = "\u{1F3F4}\u{E0067}\u{E0062}\u{E0073}";
        assert!(fires(text, "tag-block"));
    }

    #[test]
    fn balanced_isolate_around_hebrew_scores_zero_from_bidi_signals() {
        let text = "The word \u{2066}\u{05E9}\u{05DC}\u{05D5}\u{05DD}\u{2069} means peace.";
        assert_eq!(class_count(text, "unbalanced-bidi"), None);
        assert_eq!(class_count(text, "bidi-control-without-rtl"), None);
        assert_eq!(class_count(text, "directional-mark-without-rtl"), None);
        assert_eq!(total(text), 0.0, "evidence: {:?}", score(text).evidence);
    }

    #[test]
    fn balanced_embeddings_around_hebrew_score_zero() {
        let text = "\u{202A}\u{05E9}\u{05DC}\u{05D5}\u{05DD}\u{202C} ok";
        assert_eq!(class_count(text, "unbalanced-bidi"), None);
        assert_eq!(class_count(text, "bidi-control-without-rtl"), None);
    }

    #[test]
    fn nested_balanced_bidi_scores_zero() {
        let text = "\u{202A}a\u{2066}\u{05D1}\u{2069}c\u{202C}";
        assert_eq!(class_count(text, "unbalanced-bidi"), None);
    }

    #[test]
    fn zwnj_between_persian_letters_scores_zero() {
        // mi-khoram: ZWNJ is required orthography inside Persian words.
        let text = "\u{0645}\u{06CC}\u{200C}\u{062E}\u{0648}\u{0631}\u{0645}";
        assert_eq!(class_count(text, "zero-width-in-word"), None);
        assert_eq!(class_count(text, "zero-width-run"), None);
        assert_eq!(class_count(text, "directional-mark-without-rtl"), None);
        assert_eq!(total(text), 0.0, "evidence: {:?}", score(text).evidence);
    }

    #[test]
    fn zwj_between_devanagari_and_tamil_letters_scores_zero() {
        let deva = "\u{0915}\u{094D}\u{0937}";
        let tamil = "\u{0B95}\u{0BCD}\u{0BB7}";
        for text in [deva, tamil] {
            assert_eq!(class_count(text, "zero-width-in-word"), None, "{text}");
            assert_eq!(total(text), 0.0, "{text}: {:?}", score(text).evidence);
        }
    }

    #[test]
    fn zwj_between_emoji_scores_zero() {
        let text = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}";
        assert_eq!(class_count(text, "zero-width-in-word"), None);
        assert_eq!(class_count(text, "zero-width-run"), None);
        assert_eq!(total(text), 0.0, "evidence: {:?}", score(text).evidence);
    }

    #[test]
    fn single_vs16_after_emoji_base_scores_zero() {
        let text = "\u{2764}\u{FE0F} nice";
        assert_eq!(class_count(text, "variation-selector-anomaly"), None);
        assert_eq!(total(text), 0.0, "evidence: {:?}", score(text).evidence);
    }

    #[test]
    fn single_vs15_after_symbol_base_scores_zero() {
        let text = "\u{2714}\u{FE0E} done";
        assert_eq!(class_count(text, "variation-selector-anomaly"), None);
    }

    #[test]
    fn keycap_sequence_scores_zero() {
        let text = "Press 1\u{FE0F}\u{20E3} for sales";
        assert_eq!(total(text), 0.0, "evidence: {:?}", score(text).evidence);
    }

    #[test]
    fn soft_hyphen_subwords_with_one_shy_and_six_letters_do_not_fire() {
        // A single hyphenation point inside a 6+ letter token is legitimate
        // hyphenation and stays silent.
        for token in ["bor\u{00AD}tack", "quel\u{00AD}vane\u{00AD}tir"] {
            assert_eq!(class_count(token, "soft-hyphen-anomaly"), None, "{token}");
        }
    }

    #[test]
    fn soft_hyphen_fully_hyphenated_long_compound_does_not_fire() {
        // Justified typesetting puts a soft hyphen at every syllable boundary
        // of a long compound, all inside one token; 3 breaks across 18
        // letters is sparser than one per three letters, so this is the
        // legitimate shape and stays silent.
        let text = "flum\u{00AD}ber\u{00AD}tack\u{00AD}selig";
        assert_eq!(class_count(text, "soft-hyphen-anomaly"), None);
        assert_eq!(total(text), 0.0, "evidence: {:?}", score(text).evidence);
    }

    #[test]
    fn russian_sentence_quoting_kubernetes_scores_zero_from_mixed_script() {
        let text =
            "\u{041C}\u{044B} \u{0438}\u{0441}\u{043F}\u{043E}\u{043B}\u{044C}\u{0437}\u{0443}\u{0435}\u{043C} Kubernetes \u{0434}\u{043B}\u{044F} \u{043E}\u{0440}\u{043A}\u{0435}\u{0441}\u{0442}\u{0440}\u{0430}\u{0446}\u{0438}\u{0438}.";
        assert_eq!(class_count(text, "mixed-script-word"), None);
        assert_eq!(total(text), 0.0, "evidence: {:?}", score(text).evidence);
    }

    #[test]
    fn fullwidth_latin_inside_cjk_text_scores_zero() {
        let text = "\u{FF2A}\u{FF21}\u{FF30}\u{FF21}\u{FF4E} \u{306F} \u{65E5}\u{672C}\u{8A9E} \u{3067}\u{3059}";
        assert_eq!(class_count(text, "fullwidth-latin-without-cjk"), None);
        assert_eq!(total(text), 0.0, "evidence: {:?}", score(text).evidence);
    }

    #[test]
    fn fires_fullwidth_latin_despite_ideographic_space_and_fullwidth_punctuation() {
        // The ideographic space and fullwidth punctuation travel with the
        // technique, so they are not CJK-script evidence and cannot excuse
        // the fullwidth Latin.
        let text = "\u{FF38}\u{FF39}\u{FF3A}\u{3000}\u{FF1A}";
        let (count, contribution) =
            class_count(text, "fullwidth-latin-without-cjk").expect("should fire");
        assert_eq!(count, 3);
        assert_eq!(contribution, 6.0); // 2.0 * min(3, 3)
    }

    #[test]
    fn invisible_operator_inside_math_text_scores_zero() {
        let text = "let x \u{2062} y \u{2208} \u{211D}";
        assert_eq!(class_count(text, "invisible-operator-outside-math"), None);
    }

    #[test]
    fn plain_ascii_prose_scores_zero() {
        assert_eq!(
            total("Hello, I was charged twice for my March subscription."),
            0.0
        );
        assert_eq!(total(""), 0.0);
    }

    #[test]
    fn scores_are_deterministic() {
        let text = "abo\u{200C}ut \u{0430}pples \u{202E}";
        let a = score(text);
        let b = score(text);
        assert_eq!(a, b);
    }

    #[test]
    fn cap_limits_repetition() {
        let many: String = "\u{E0041}".repeat(100);
        let (_, contribution) = class_count(&many, "tag-block").unwrap();
        assert_eq!(contribution, 12.0, "100 tag chars must count as capped 3");
    }
}
