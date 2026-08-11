# SPDX-License-Identifier: Apache-2.0
"""Text folding and term matching that behave the same in all 26 languages.

Shared by the four detectors ported from the Guardrails Hub. It exists because every
one of those validators matches text against a list of strings, and every one of them
does it in a way that is correct in English and wrong somewhere in Europe. The bugs are
not exotic. They are the first thing you hit in Greek, German, Turkish or Romanian, and
each is reproduced as a test in tests/test_multilingual.py.

What folding fixes, with the case that proves it
------------------------------------------------

**casefold, not lower.** `str.lower()` leaves German and Greek broken.
`"Straße".lower()` is `"straße"` and `"STRASSE".lower()` is `"strasse"`, so the two
spellings of one word do not match. `casefold()` maps both to `"strasse"`. In Greek the
problem is narrower than it first looks: Python's `lower()` does implement the
final-sigma rule, so `"ΛΑΘΟΣ".lower()` correctly ends in ς. What it does not do is
*unify* ς with σ, so the same word spelled with a medial sigma at the end, which is what
any source that lowercased without that rule produces and what a non-Greek keyboard
tends to produce, stays a different string. casefold maps both onto σ. The upstream
`ban_list` validator uses `.lower()`.

**Dotted capital I.** `"İ".casefold()` is two characters, `i` followed by U+0307
COMBINING DOT ABOVE, so casefolding alone leaves Turkish `"İSTANBUL"` unable to match
`"istanbul"`. Mapped explicitly rather than by stripping U+0307 everywhere, because
Maltese ż and Lithuanian ė decompose to a dot above too and stripping it would silently
merge distinct letters.

**Comma-below and cedilla are two encodings of one Romanian letter.** ș is U+0219 and
ş is U+015F, both in daily use for the same letter because a generation of software
emitted the Turkish cedilla form. NFC does not unify them: they normalise to themselves.
So they are unified here, and ț/ţ with them. This is not the same as ignoring
diacritics, which is a separate opt-in below: unifying two spellings of one letter is
lossless, dropping a diacritic is not.

**Decomposed input.** The same word arrives precomposed or decomposed depending on the
platform that produced it. Folding walks base-plus-combining-marks clusters and
normalises each cluster, so both spellings fold alike without an NFC pass over the whole
string, which would move every offset and make spans point at the wrong characters.

**Zero-width characters are an evasion, not a typo.** `ac<U+200B>me` reads as `acme` and
matches nothing. Characters in Unicode category Cf are dropped during folding, and the
span still covers them, so a redaction removes the whole run.

Offsets survive all of it
-------------------------

Folding changes length: ß becomes two characters, a zero-width character becomes none,
a whitespace run becomes one space. A detector that folded text and then reported an
offset into the folded string would hand the caller a span that does not index their
string, and the engine would redact the wrong characters. So `fold` returns the offset
of every folded character in the original, and `Folded.span` converts back. This is the
part that is easy to get wrong and the reason the whole thing is one module with its
own tests rather than a helper inside each detector.
"""

from __future__ import annotations

import html.entities
import re
import unicodedata
from functools import lru_cache
from typing import Final, Literal, NamedTuple

#: The two normalisation forms this module uses. NFD and NFKD are absent because a
#: decomposed result would reintroduce the combining marks that cluster folding just
#: resolved.
Form = Literal["NFC", "NFKC"]

#: Two encodings of one letter, plus the dotted capital I. Applied before casefold, on
#: the raw cluster, so that every later step sees one spelling.
#:
#: Deliberately small. It unifies characters that are the same letter, and nothing else.
#: The moment it starts mapping ö to o it becomes diacritic folding, which is a
#: different operation with different false positives, and it is opt-in below.
_SAME_LETTER: Final = str.maketrans(
    {
        0x0130: "i",  # İ, whose casefold is i + combining dot above
        0x015E: "ș",  # Ş, cedilla form of the Romanian letter
        0x015F: "ș",  # ş
        0x0218: "ș",  # Ș, comma form
        0x0162: "ț",  # Ţ
        0x0163: "ț",  # ţ
        0x021A: "ț",  # Ț
        # Typographic apostrophes onto the ASCII one. A French, Irish or Italian
        # phrase is written `j'ai` in a term list and arrives as `j’ai` from any
        # editor with smart quotes on, and NFC does not bring the two together.
        # Without this the elided languages match strictly less than the others.
        0x2019: "'",  # right single quotation mark
        0x02BC: "'",  # modifier letter apostrophe
        0x00B4: "'",  # acute accent used as an apostrophe
    }
)

#: HTML character references, numeric and named. Only consulted when a caller asks for
#: entity decoding, which is the markup_injection case: `&#106;avascript:` is the same
#: payload as `javascript:` and has to fold to the same text.
_ENTITY: Final = re.compile(
    r"&(?:#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});"
)

_WHITESPACE_RUN: Final = re.compile(r"\s")


class Folded(NamedTuple):
    """Folded text, plus where each of its characters came from.

    `starts[i]` and `ends[i]` bracket the original characters that produced `text[i]`.
    They are not always one character wide: a decomposed cluster contributes several,
    a decoded entity contributes the whole `&#106;`, and both fold to one character.
    """

    text: str
    starts: tuple[int, ...]
    ends: tuple[int, ...]

    def span(self, start: int, end: int) -> tuple[int, int]:
        """Convert a half-open span in the folded text to one in the original.

        Raises on an empty span rather than returning a zero-width one, because an
        empty match is a bug in the caller's pattern and a zero-width span in a
        Finding would redact nothing while claiming to have redacted something.
        """
        if end <= start:
            raise ValueError("an empty folded span has no original counterpart")
        return (self.starts[start], self.ends[end - 1])


def fold(
    text: str,
    *,
    diacritics: bool = False,
    compat: bool = False,
    entities: bool = False,
) -> Folded:
    """Casefold, unify one-letter spellings, collapse whitespace, keep the offsets.

    diacritics
        Also strip combining marks, so `ă` matches `a`. Off by default. It is the
        difference between matching a word someone typed without diacritics, which
        happens constantly in Romanian and Turkish, and matching a different word,
        which also happens: Swedish `far` and `fär` are not the same. A policy that
        wants the first has to accept the second, so it says so.
    compat
        Normalise NFKC rather than NFC, folding full-width and other compatibility
        forms onto their ASCII counterparts. This is for markup rather than prose:
        full-width `ｊａｖａｓｃｒｉｐｔ:` is a script URL and a browser treats it as
        one. It is off for prose because NFKC also rewrites ligatures and superscripts
        in ordinary text.
    entities
        Decode HTML character references. Same reason as compat, same caveat: only
        useful where the text is markup.
    """
    form: Form = "NFKC" if compat else "NFC"
    out: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    index = 0
    length = len(text)

    while index < length:
        char = text[index]

        if entities and char == "&":
            match = _ENTITY.match(text, index)
            decoded = _decode_entity(match.group()) if match is not None else None
            if match is not None and decoded is not None:
                _emit(
                    out,
                    starts,
                    ends,
                    _reduce(decoded, form, diacritics),
                    index,
                    match.end(),
                )
                index = match.end()
                continue

        # A cluster is a base character plus the combining marks that belong to it.
        # Taken together so that decomposed input normalises like precomposed input
        # without an NFC pass over the whole string, which would move every offset.
        end = index + 1
        while end < length and unicodedata.combining(text[end]):
            end += 1
        cluster = text[index:end]

        if all(unicodedata.category(c) == "Cf" for c in cluster):
            # Zero-width and other format characters contribute nothing to the folded
            # text. They keep their place in the original, so a span that steps over
            # one still covers it and a redaction removes it.
            index = end
            continue

        if _WHITESPACE_RUN.match(cluster):
            if out and out[-1] == " ":
                # Extend the run so the span of the collapsed space covers all of it.
                ends[-1] = end
            else:
                _emit(out, starts, ends, " ", index, end)
            index = end
            continue

        _emit(out, starts, ends, _reduce(cluster, form, diacritics), index, end)
        index = end

    return Folded("".join(out), tuple(starts), tuple(ends))


def _decode_entity(reference: str) -> str | None:
    """One HTML character reference to its character, or None if it is not one.

    Deliberately stricter than `html.unescape`. That function resolves a named
    reference from a prefix, because HTML5 permits references without a trailing
    semicolon, so it turns the ordinary word `&notareference;` into `¬areference;`.
    Harmless for the patterns here, but it means folded text stops being a faithful
    reading of the original, and the next person to add a pattern would be matching
    against something they cannot predict. An exact lookup keeps the folded text
    explainable: a reference decodes, and anything else is literal.
    """
    body = reference[1:-1]
    if body.startswith("#"):
        digits = body[1:]
        try:
            code = int(digits[1:], 16) if digits[:1] in ("x", "X") else int(digits)
        except ValueError:  # pragma: no cover - the pattern already constrains this
            return None
        # Surrogates and out-of-range values are not characters. chr would raise on
        # the second and produce an unpaired surrogate on the first.
        if code > 0x10FFFF or 0xD800 <= code <= 0xDFFF:
            return None
        return chr(code)
    return html.entities.html5.get(f"{body};")


def _reduce(cluster: str, form: Form, diacritics: bool) -> str:
    """One cluster to its folded characters. May be zero, one, or several."""
    normalised = unicodedata.normalize(form, cluster).translate(_SAME_LETTER)
    folded = normalised.casefold()
    if diacritics:
        folded = "".join(
            c
            for c in unicodedata.normalize("NFD", folded)
            if unicodedata.category(c) != "Mn"
        )
    return folded


def _emit(
    out: list[str],
    starts: list[int],
    ends: list[int],
    produced: str,
    start: int,
    end: int,
) -> None:
    for char in produced:
        out.append(char)
        starts.append(start)
        ends.append(end)


def fold_text(text: str, **options: bool) -> str:
    """Just the folded string, for a term list where no offset is ever needed."""
    return fold(text, **options).text


@lru_cache(maxsize=256)
def compile_terms(terms: tuple[str, ...], whole_words: bool) -> re.Pattern[str] | None:
    """One alternation over already-folded terms, longest first.

    Longest first so the reported span covers the fullest match rather than stopping at
    whichever alternative happens to be listed earlier.

    whole_words
        Wrap the alternation in lookarounds so a term only matches on a word boundary.
        On by default at every call site, and it is the fix for the upstream
        `ban_list` behaviour: that validator strips every space from the text before
        searching, so banning `arse` flags `car sedan`. Lookarounds rather than \\b
        because a term may begin or end with a non-word character, where \\b asserts
        the opposite of what is wanted.

    Returns None for an empty term list. A pattern built from no alternatives matches
    the empty string everywhere, which would be worse than matching nothing: every
    caller here treats None as "nothing configured" and says so out loud.
    """
    # Stripped, because a term that is only whitespace would compile into an
    # alternative that matches a space anywhere in the text, and a policy listing an
    # accidental blank line would turn the detector into a finding per word.
    cleaned = sorted(
        {stripped for term in terms if (stripped := term.strip())},
        key=len,
        reverse=True,
    )
    if not cleaned:
        return None
    body = "|".join(re.escape(term) for term in cleaned)
    if whole_words:
        return re.compile(rf"(?<!\w)(?:{body})(?!\w)")
    return re.compile(f"(?:{body})")


def find_terms(
    haystack: Folded,
    terms: tuple[str, ...],
    *,
    whole_words: bool = True,
) -> list[tuple[int, int, str]]:
    """Every non-overlapping term match, as spans in the original text.

    Returns (start, end, matched_folded_term). The term is the folded spelling rather
    than the caller's, because the caller's spelling and the text's spelling can differ
    in case and encoding and the folded form is the one that actually matched.
    """
    pattern = compile_terms(terms, whole_words)
    if pattern is None:
        return []
    return [
        (*haystack.span(match.start(), match.end()), match.group())
        for match in pattern.finditer(haystack.text)
    ]


def shingles(text: str, size: int) -> list[str]:
    """Overlapping word n-grams, for measuring how much of one text is inside another.

    Words rather than characters because a character n-gram of a European language is
    mostly a measure of its alphabet: two unrelated Finnish sentences share far more
    5-character runs than two unrelated English ones, so a character-based threshold
    would mean a different thing in every language.
    """
    words = text.split()
    if len(words) <= size:
        return [" ".join(words)] if words else []
    return [" ".join(words[i : i + size]) for i in range(len(words) - size + 1)]
