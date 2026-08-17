# SPDX-License-Identifier: Apache-2.0
"""Conflicts between a claim and its source that a rule can settle without a model.

The same division of labour as `checksummed.py`, and for the same reason. There, the PII
tagger covers 4 of 19 characters of some card numbers and `checksummed.py` finds every
Luhn-valid PAN with no model at all, so the leak is closed whatever the model does. Here
the
groundedness cross-encoder called a candidate asserting `4.3 percent` grounded at 0.9972
against a source that says `4.2 percent`, and no amount of retraining makes that safe to
rely on. A number that disagrees with its source is checkable, so it gets checked.

## The rule, and the shape of the evidence for it

A candidate whose content words all appear in its source, except for one or more
numerals or
absolute quantifiers, is asserting something the source does not. Measured on 2026-08-17
against the 42 hand-written probes in the training repository: **9 rows match this
description and all 9 are gold-ungrounded**, with no false positives.

    missing content words              gold        rows
    ['4.3'] ['3.2'] ['29'] ['15'] ...  ungrounded     6
    ['all']                            ungrounded     3

Put in front of the binary groundedness model it takes the probe set from 29 of 42 to
31,
0.6905 to 0.7381, fixing an altered `4.3 percent` the model called grounded at 0.9972
and an
`All withdrawals` it called grounded at 0.9988, and breaking nothing that was already
right.

## The direction that was refused, which is the more useful half of the finding

The obvious companion rule is the reverse: if *every* content word of the candidate
appears
in the source, call it grounded. That was measured on the same 42 rows and is **5 right
and 4
wrong**, so it is not implemented.

The four counterexamples are why, and they are the shapes this detector is worst at. A
candidate can quote a clause verbatim and still be false, by dropping the qualifier that
governed it or by reversing its polarity:

- source: withdrawals incur a fee within the first twelve months, and are free after.
  candidate: "Withdrawals are free of charge and may be made without notice." Every word
  is
  in the source. The claim is still wrong, because the source made it conditional.
- source: overpayments up to 10 percent per year may be made without charge.
  candidate: "Overpayments may be made without charge." Same shape.

So lexical containment is evidence of nothing on its own, and this module only ever
moves a
verdict toward *not grounded*. That asymmetry is deliberate: a false "not grounded"
costs a
caller caution, and a false "grounded" puts an unsupported claim in front of their
customer.

## Languages

The numeric half is language independent, because a digit is a digit in all 26. The
quantifier half needs a word list, and `data/absolute_quantifiers.yaml` carries one per
language with `reviewed: false` where no native speaker has checked it.

An incomplete list here is safe in a way an incomplete numeral list would not be. This
module
only *matches* words, so a missing entry means a conflict goes unreported, which is the
same
outcome as not having the rule. Nothing is generated from the list, so it cannot produce
text
a native reader would not write.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Final

# : Reported labels. Both mean the claim is not grounded, and they are separate because
# an
#: operator reading a record needs to know whether a figure was altered or a claim was
# : broadened: the first is usually a transcription error and the second is usually a
# summary
#: overreaching.
NUMERIC_CONFLICT: Final = "numeric_conflict"
SCOPE_WIDENED: Final = "scope_widened"

# : Word characters plus the separators a number can carry inside it, so `4.3`, `1,000`
# and
# : `10%` survive tokenisation as single tokens rather than splitting into pieces that
# would
#: each look like a different missing word.
_TOKEN = re.compile(r"[\w.,%]+", re.UNICODE)

_HAS_DIGIT = re.compile(r"\d")

# : Function words carry no claim, so their absence from a source means nothing. Kept
# small
#: and English-only on purpose: a stopword list per language is a much larger commitment
#: than this rule needs, and a false *negative* here is harmless. A content word wrongly
#: treated as content only makes the rule fire less often.
_ENGLISH_FUNCTION_WORDS: Final = frozenset(
    [
        "a",
        "an",
        "the",
        "of",
        "to",
        "and",
        "or",
        "in",
        "on",
        "at",
        "by",
        "for",
        "from",
        "with",
        "as",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "being",
        "it",
        "its",
        "this",
        "that",
        "these",
        "those",
        "there",
        "their",
        "his",
        "her",
        "our",
        "your",
        "my",
        "will",
        "would",
        "may",
        "might",
        "can",
        "could",
        "shall",
        "should",
        "must",
        "do",
        "does",
        "did",
        "has",
        "have",
        "had",
        "not",
        "no",
        "nor",
        "but",
        "if",
        "then",
        "than",
        "so",
        "such",
        "which",
        "who",
        "whom",
        "whose",
        "what",
        "when",
        "where",
        "how",
        "also",
        "into",
        "over",
        "under",
        "between",
    ]
)


#: One entry per language, the same shape and location as the other phrasing files.
QUANTIFIERS_PATH: Final = (
    Path(__file__).resolve().parent.parent / "data" / "absolute_quantifiers.yaml"
)


@lru_cache(maxsize=1)
def _quantifiers() -> frozenset[str]:
    """Absolute quantifiers in every supported language, folded for comparison."""
    import yaml

    from flowx_border.detectors.multilingual import fold_text

    raw = yaml.safe_load(QUANTIFIERS_PATH.read_text(encoding="utf-8"))
    words: set[str] = set()
    for entry in (raw or {}).get("languages", {}).values():
        for word in entry.get("words", ()):
            folded = fold_text(str(word))
            # Single tokens only. Comparison happens token by token, so a two-word entry
            # such as Turkish `her zaman` or Estonian `mitte kunagi` could never match:
            # one half would be missing from the source and would not itself be a
            # quantifier, and the rule would decline. They stay in the file because they
            # are correct data and a phrase matcher may want them later, and they are
            # skipped here rather than silently half-matched.
            if " " in folded:
                continue
            words.add(folded)
    return frozenset(words)


def _tokens(text: str) -> list[str]:
    from flowx_border.detectors.multilingual import fold_text

    return [fold_text(match.group(0)).strip(".,%") for match in _TOKEN.finditer(text)]


def _is_number(token: str) -> bool:
    return bool(_HAS_DIGIT.search(token))


def conflict(source: str, candidate: str) -> tuple[str, tuple[str, ...]] | None:
    """The conflict this candidate has with this source, or None.

    Returns the label and the tokens that caused it, so a caller can put the actual
    disagreeing figure in an evidence record rather than only a score.

    Fires only when *every* content word of the candidate is present in the source
    except
    the numerals or quantifiers. A candidate that also introduces new content words is
    saying something this rule cannot adjudicate, and it is left to the model.
    """
    candidate_tokens = _tokens(candidate)
    if not candidate_tokens:
        return None
    source_tokens = set(_tokens(source))

    missing = [
        token
        for token in candidate_tokens
        if token and token not in source_tokens and token not in _ENGLISH_FUNCTION_WORDS
    ]
    if not missing:
        # Full containment. Evidence of nothing, per the module docstring: a verbatim
        # clause can still drop the qualifier that governed it.
        return None

    quantifiers = _quantifiers()
    numbers = tuple(token for token in missing if _is_number(token))
    quants = tuple(token for token in missing if token in quantifiers)
    if len(numbers) + len(quants) != len(missing):
        # Something else is new, so the candidate is making a claim the source may or
        # may
        # not support and only the model can say. Not this rule's question.
        return None

    if numbers:
        # A number the source does not contain, in a candidate that is otherwise the
        # source's own words. Reported ahead of a widened scope because an altered
        # figure
        # is the more specific finding.
        return NUMERIC_CONFLICT, numbers
    return SCOPE_WIDENED, quants
