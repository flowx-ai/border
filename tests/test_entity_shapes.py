# SPDX-License-Identifier: Apache-2.0
"""Tests for the shape gate, including the four false positives that caused it.

The gate exists because a held-out evaluation caught piiguard tagging number words in
prose. Those four cases are the first tests here, as regressions.

The rest are about the direction of failure, which is the part that matters in a
redactor. A gate that drops a real entity turns visible noise into an invisible hole in
a redaction, so most of these assert that something is *kept*.
"""

from __future__ import annotations

import pytest

from flowx_border.detectors.entity_shapes import (
    checksum_state,
    corrected_label,
    iban_ok,
    is_possible,
    luhn_ok,
)

# ---------------------------------------------------- the four that caused this module


@pytest.mark.parametrize(
    ("entity", "value"),
    [
        ("EMAIL", "nine"),
        ("DATE", "five."),
        ("DATE", "fem."),
    ],
)
def test_the_measured_false_positives_are_rejected(entity: str, value: str) -> None:
    """Three of the four die here. Measured on 2026-08-12 in English and Swedish."""
    assert not is_possible(entity, value)


def test_the_person_false_positive_survives_and_that_is_recorded() -> None:
    """The fourth one, and the honest limit of this module.

    `nio` was tagged PERSON in Swedish. A name is any string, so there is nothing to
    check and this asserts the gap rather than hiding it. Closing it needs the corpus to
    contain sentences with no entities, which is a training-side fix.
    """
    assert is_possible("PERSON", "nio")


# ------------------------------------------------------------------ what gets dropped


@pytest.mark.parametrize(
    ("entity", "value"),
    [
        ("EMAIL", "not an address"),
        ("EMAIL", "user@localhost"),  # no dot in the domain
        ("DATE", "Tuesday"),
        ("PHONE", "1234"),
        ("CARD", "4111 1111"),
        ("NATIONAL_ID", "AB1"),
        ("IBAN", "GB"),
    ],
)
def test_the_impossible_is_dropped(entity: str, value: str) -> None:
    assert not is_possible(entity, value)


def test_an_empty_or_punctuation_only_span_is_dropped() -> None:
    for value in ("", "   ", ".", "()"):
        assert not is_possible("PERSON", value), value


# ------------------------------------------------------------------- what gets kept


@pytest.mark.parametrize(
    ("entity", "value"),
    [
        ("EMAIL", "marie.dubois@banque.fr"),
        ("EMAIL", "p.wainwright@example.co.uk"),
        ("DATE", "14 March 2024"),
        ("DATE", "2024-03-14"),
        ("DATE", "14 martie 2024."),
        ("PHONE", "+44 20 7946 0812"),
        ("PHONE", "0749 118 226"),
        ("CARD", "4111 1111 1111 1111"),
        ("IBAN", "GB29 NWBK 6016 1331 9268 19"),
        ("IBAN", "RO49 AAAA 1B31 0075 9384 0000"),
        ("NATIONAL_ID", "1920315123457"),
        ("PERSON", "Helen Marsh"),
        ("PERSON", "Ελένη Παπαδοπούλου"),
        ("PERSON", "Rəşad Məmmədov"),
    ],
)
def test_a_real_entity_is_kept(entity: str, value: str) -> None:
    assert is_possible(entity, value)


def test_trailing_sentence_punctuation_does_not_reject_a_real_date() -> None:
    """`five.` is rejected for having no digit, not for the full stop.

    Which is the distinction that matters: a date at the end of a sentence carries the
    same full stop and must survive.
    """
    assert is_possible("DATE", "14 March 2024.")
    assert not is_possible("DATE", "five.")


def test_an_unknown_entity_type_is_kept() -> None:
    """A label this module has not been taught must not silently stop being redacted."""
    assert is_possible("PASSPORT", "anything at all")


# ------------------------------------------------------ checksums note, never drop


def test_luhn_accepts_a_valid_card_and_rejects_a_mutated_one() -> None:
    assert luhn_ok("4111111111111111")
    assert not luhn_ok("4111111111111112")


def test_iban_mod97_accepts_a_valid_iban_and_rejects_a_mutated_one() -> None:
    assert iban_ok("GB29 NWBK 6016 1331 9268 19")
    assert not iban_ok("GB29 NWBK 6016 1331 9268 18")


def test_a_failing_checksum_is_still_a_possible_entity() -> None:
    """The design decision worth arguing about, asserted.

    `4111 1111 1111 1112` fails Luhn and is obviously still a card number to redact. A
    checksum failure is as likely to be a typo, a test number, or a span whose boundary
    the model moved, and all three are still personal data. So the gate notes it and the
    entity is kept.
    """
    assert checksum_state("CARD", "4111 1111 1111 1112") is False
    assert is_possible("CARD", "4111 1111 1111 1112")

    assert checksum_state("IBAN", "GB29 NWBK 6016 1331 9268 18") is False
    assert is_possible("IBAN", "GB29 NWBK 6016 1331 9268 18")


def test_a_clipped_iban_is_kept_even_though_it_cannot_validate() -> None:
    """A boundary the model got wrong still leaks most of an account number."""
    clipped = "GB29 NWBK 6016 1331 9268 1"
    assert checksum_state("IBAN", clipped) is False
    assert is_possible("IBAN", clipped)


def test_a_type_with_no_checksum_returns_none_rather_than_false() -> None:
    """None is not a failure, and a caller treating it as one would drop everything."""
    for entity in ("PERSON", "EMAIL", "PHONE", "DATE", "NATIONAL_ID"):
        assert checksum_state(entity, "whatever") is None, entity


def test_a_valid_checksum_returns_true() -> None:
    assert checksum_state("CARD", "4111 1111 1111 1111") is True
    assert checksum_state("IBAN", "GB29 NWBK 6016 1331 9268 19") is True


# ------------------------------------------------- through the detector, not around it


def test_the_gate_is_case_insensitive_about_the_entity_name() -> None:
    """The bug this test exists for: the gate silently did nothing.

    The model's labels are lower case and this module's names are not, so every
    comparison missed and `is_possible` returned True for everything. A `DATE` span
    reading `March` survived a check that requires a digit, and the rest of this file
    did not catch it because it calls the function directly with the upper case name.

    A gate that passes everything is worse than no gate, because the record then says a
    shape check ran.
    """
    for name in ("DATE", "date", "Date"):
        assert not is_possible(name, "March"), name
        assert is_possible(name, "14 March 2024"), name
    for name in ("EMAIL", "email"):
        assert not is_possible(name, "nine"), name
    for name in ("CARD", "card"):
        assert checksum_state(name, "4111 1111 1111 1111") is True, name


def test_a_span_too_short_to_be_an_iban_is_dropped() -> None:
    """The measured false positives, which were product descriptions and a battery.

    Every one of these passed the rule that stood here until 2026-08-16, two letters and
    four digits, because a dimension list has both. ISO 13616 puts the floor at 15
    characters, so none of them can be an IBAN and dropping costs no recall.
    """
    for value in ("mm × 80 mm × 45 mm", "5000 mAh", '6,5", 128 GB'):
        assert not is_possible("IBAN", value), value


def test_a_real_iban_survives_the_length_floor() -> None:
    """Both presentation forms, because the compact one is 24 characters and the spaced
    one is 29, and a floor measured over the wrong alphabet would pass one and fail the
    other."""
    for value in ("RO49 AAAA 1B31 0075 9384 0000", "RO49AAAA1B31007593840000"):
        assert is_possible("IBAN", value)
        assert checksum_state("IBAN", value) is True


def test_the_iban_floor_agrees_with_the_checksum_pass() -> None:
    """The two modules read the same number off the same standard and must not drift.

    `checksummed.py` needs the floor to scan raw text and this module needs it to judge
    a span. Pinning them equal here rather than sharing a constant keeps each module
    readable on its own, which is worth one test.
    """
    from flowx_border.detectors import checksummed
    from flowx_border.detectors.entity_shapes import _IBAN_MIN

    assert _IBAN_MIN == checksummed._IBAN_MIN == 15


def test_dropping_a_clipped_iban_span_leaves_no_hole() -> None:
    """The claim the length floor rests on, tested rather than asserted in a comment.

    The floor reverses a decision that stood on the grounds that a span which clipped an
    IBAN should be redacted rather than dropped. That was right about the risk. What
    makes the reversal safe is that `checksummed.py` scans the raw text for mod-97-valid
    runs without consulting the model, so the clipped span dies in `is_possible` and the
    whole IBAN is found anyway.

    Here the model is imagined to have tagged only `RO49 AAAA`, ten characters, which
    the floor rejects. The account number still comes back covered.
    """
    from flowx_border.detectors.checksummed import supplement

    iban = "RO49 AAAA 1B31 0075 9384 0000"
    text = f"Send it to {iban} before Friday."
    clipped = (text.index(iban), text.index(iban) + len("RO49 AAAA"))

    assert not is_possible("IBAN", text[clipped[0] : clipped[1]])

    # The gate has dropped it, so the model contributes nothing at all here.
    found = supplement(text, {})
    covered = [
        (start, end)
        for (start, end), (entity, _) in found.items()
        if entity == "iban" and text[start:end] == iban
    ]
    assert covered, f"the checksum pass did not find {iban!r} in {text!r}"


def test_an_address_the_model_called_a_person_is_relabelled() -> None:
    """The regression the adopted piiguard artifact introduced, in hr, sl and fr.

    The span was always whole, so nothing leaked and the redactor removed the same
    characters either way. What broke was the evidence record, which said a person where
    an address was, and `output_leakage`, which looks for a leaked email by name.
    """
    for value in (
        "ivan.horvat@primjer.hr",
        "janez.novak@primer.si",
        "marie.dubois@bank.fr",
    ):
        assert corrected_label("person", value) == "email"
        assert corrected_label("national_id", value) == "email"


def test_a_real_name_is_not_relabelled() -> None:
    """Nothing without an address in it is touched, which is nearly every span."""
    for value in ("Ivan Horvat", "Kovács Péter", "Bərdə", "14 March 2024", ""):
        assert corrected_label("person", value) is None


def test_a_sentence_containing_an_address_is_not_relabelled() -> None:
    """Only a span that *is* an address, never one that merely contains one.

    A span covering a whole clause is one whose boundaries the model got wrong, and
    renaming it would move the `email` label onto text that is not the address. Left
    alone, it stays a boundary problem rather than becoming a labelling lie.
    """
    sentence = "Ivan Horvat, e-posta ivan.horvat@primjer.hr"
    assert corrected_label("person", sentence) is None


def test_an_address_already_labelled_email_is_left_alone() -> None:
    assert corrected_label("email", "ivan.horvat@primjer.hr") is None
