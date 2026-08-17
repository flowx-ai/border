# SPDX-License-Identifier: Apache-2.0
"""The rule half of groundedness: conflicts settled without a model.

Two things this file is careful about, both of them the reason the module exists.

The rule only ever moves a verdict toward not-grounded, so the tests that matter most
are
the ones asserting it stays silent. A false `numeric_conflict` would report a caller's
correct summary as unsupported, and unlike a missed conflict that is visible damage.

And the refused direction is tested as a refusal. If a later change makes full lexical
containment imply grounded, `test_full_containment_is_never_grounding` fails, because
that
was measured at 5 right and 4 wrong on the hand-written probes and the four wrong ones
are
the shapes this detector is worst at.
"""

from __future__ import annotations

import yaml

from flowx_border.detectors.claim_conflict import (
    NUMERIC_CONFLICT,
    QUANTIFIERS_PATH,
    SCOPE_WIDENED,
    conflict,
)
from flowx_border.detectors.multilingual import LANGUAGES

# : The probe source the training repository uses, kept verbatim so a figure measured
# there
#: and a figure measured here describe the same input.
SOURCE = (
    "The fixed rate of 4.2 percent applies for the first five years of the loan. "
    "Overpayments of up to 10 percent of the outstanding balance per calendar year may "
    "be made without charge. Overpayments beyond that incur a fee of 250 EUR."
)

WITHDRAWALS = (
    "Withdrawals made within the first twelve months of opening incur a "
    "handling fee of 5 EUR per transaction. After twelve months have elapsed, "
    "withdrawals are free of "
    "charge and may be made without notice."
)


# ------------------------------------------------------------------ it fires when it
# should


def test_an_altered_figure_is_a_numeric_conflict() -> None:
    found = conflict(
        SOURCE,
        "The fixed rate of 4.3 percent applies for the first five years of the loan.",
    )
    assert found is not None
    label, tokens = found
    assert label == NUMERIC_CONFLICT
    # The disagreeing figure itself, so an evidence record can name it rather than only
    # carrying a score.
    assert tokens == ("4.3",)


def test_an_added_absolute_quantifier_widens_the_scope() -> None:
    found = conflict(SOURCE, "All overpayments may be made without charge.")
    assert found is not None
    assert found[0] == SCOPE_WIDENED
    assert found[1] == ("all",)


def test_a_figure_is_reported_ahead_of_a_quantifier() -> None:
    """Both present is the more specific finding, and an operator wants the number."""
    found = conflict(
        SOURCE, "All overpayments of up to 11 percent may be made without charge."
    )
    assert found is not None
    assert found[0] == NUMERIC_CONFLICT


# ------------------------------------------------------------------ it stays silent


def test_a_faithful_restatement_is_not_a_conflict() -> None:
    assert (
        conflict(
            SOURCE, "The fixed rate of 4.2 percent applies for the first five years."
        )
        is None
    )


def test_full_containment_is_never_grounding() -> None:
    """The refused direction, pinned as a refusal.

    Every content word of this candidate is in the source and the claim is still false:
    the
    source made it conditional on the first twelve months having elapsed. Measured over
    the
    42 hand-written probes, a containment-implies-grounded rule is 5 right and 4 wrong,
    and
    all four wrong are this shape or a reversed polarity. So the rule returns None here,
    which leaves the judgement with the model rather than answering it.
    """
    assert (
        conflict(
            WITHDRAWALS,
            "Withdrawals are free of charge and may be made without notice.",
        )
        is None
    )
    assert conflict(SOURCE, "Overpayments may be made without charge.") is None


def test_a_candidate_introducing_new_content_is_left_to_the_model() -> None:
    """Not this rule's question, and answering it would be guessing."""
    assert (
        conflict(
            SOURCE,
            "The loan may be repaid early without any penalty whatsoever in year six.",
        )
        is None
    )


def test_an_empty_candidate_is_not_a_conflict() -> None:
    assert conflict(SOURCE, "") is None
    assert conflict(SOURCE, "   ") is None


def test_a_number_the_source_does_contain_is_not_a_conflict() -> None:
    """250 appears in the source, so quoting it is not a disagreement."""
    assert conflict(SOURCE, "Overpayments beyond that incur a fee of 250 EUR.") is None


# ------------------------------------------------------------------ languages


def test_the_quantifier_file_covers_every_supported_language() -> None:
    data = yaml.safe_load(QUANTIFIERS_PATH.read_text(encoding="utf-8"))
    listed = set(data["languages"])
    missing = sorted(set(LANGUAGES) - listed)
    assert not missing, f"no absolute quantifiers for: {', '.join(missing)}"
    extra = sorted(listed - set(LANGUAGES))
    assert not extra, (
        f"quantifiers for languages this library does not support: {extra}"
    )


def test_every_language_has_at_least_one_single_word_quantifier() -> None:
    """A language whose entries are all multi-word contributes nothing to the rule.

    Comparison is token by token, so `her zaman` cannot match. That is documented in the
    module and in the data file, and this asserts no language is left with only such
    entries, which would be a silent gap rather than a declared one.
    """
    data = yaml.safe_load(QUANTIFIERS_PATH.read_text(encoding="utf-8"))
    barren = sorted(
        code
        for code, entry in data["languages"].items()
        if not any(" " not in str(word) for word in entry.get("words", ()))
    )
    assert not barren, f"only multi-word quantifiers, so the rule cannot fire: {barren}"


def test_the_rule_fires_in_every_language() -> None:
    """One synthetic pair per language, so the mechanism is not English-only.

    The candidate is the source with one absolute quantifier prepended, which is the
    minimal form of the widening this reports.
    """
    data = yaml.safe_load(QUANTIFIERS_PATH.read_text(encoding="utf-8"))
    failures = []
    for code, entry in data["languages"].items():
        word = next(w for w in entry["words"] if " " not in str(w))
        source = "kontrakt beskriver betaling schedule terminy"
        found = conflict(source, f"{word} {source}")
        if found is None or found[0] != SCOPE_WIDENED:
            failures.append(f"{code}: {word!r} produced {found}")
    assert not failures, "the rule did not fire for:\n  " + "\n  ".join(failures)


def test_reviewed_flags_are_honest() -> None:
    """English is checked and nothing else is, and the file has to keep saying so.

    Flipping a flag to true without a native speaker having read the list would make
    this
    file claim a review that did not happen, which is the kind of claim this project
    treats
    as load-bearing.
    """
    data = yaml.safe_load(QUANTIFIERS_PATH.read_text(encoding="utf-8"))
    reviewed = sorted(c for c, e in data["languages"].items() if e.get("reviewed"))
    assert reviewed == ["en"], (
        f"reviewed languages are {reviewed}. If a native speaker has checked one, "
        "say so here and in the file's header; if not, the flag should be false."
    )
