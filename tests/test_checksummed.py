# SPDX-License-Identifier: Apache-2.0
"""Tests for the checksum pass, starting with the leak that caused it.

No model here, which is the point of the module: a card number and an IBAN carry their
own proof, so these run in the default suite with nothing downloaded.

Most of these assert a span rather than a label, because a span is what a redactor
consumes. `4111 1111 1111 1111` reported as a card whose span covers only `4111` is not
a partial success, it is twelve digits in the clear.
"""

from __future__ import annotations

import pytest

from flowx_border.detectors.checksummed import CARD, IBAN, find, supplement
from flowx_border.detectors.multilingual import LANGUAGES

# --------------------------------------------------------- the leak that caused this


@pytest.mark.parametrize(
    "written",
    [
        "4111111111111111",
        "4111 1111 1111 1111",
        "4111-1111-1111-1111",
        "4111.1111.1111.1111",
        # A non-breaking space, which is what a number pasted out of a PDF statement
        # carries, and what splitting on ASCII whitespace would miss.
        "4111\u00a01111\u00a01111\u00a01111",
    ],
)
def test_a_card_is_found_in_every_presentation_form(written: str) -> None:
    """Measured 2026-08-12: the model finds this only when the digits are unspaced.

    In the spaced form it tagged the first group `national_id` and missed the other
    twelve digits, which is the whole reason this module exists. Here every form the
    world writes a card number in produces one span covering all of it.
    """
    text = f"Kartennummer {written} lautet auf Anna Schmidt."
    found = find(text)
    assert [(text[s:e], label) for (s, e), label in found] == [(written, "card")]


def test_a_clipped_iban_span_is_replaced_by_the_whole_thing() -> None:
    """The other half of the same measurement, and a real disclosure.

    The model returned `AAAA 1B31 0075 9384 0000` for this, dropping `RO49`. The country
    code and check digits leaked, and because the remainder cannot pass mod-97 without
    them the shape gate also reported a checksum failure on a perfectly valid IBAN.
    """
    iban = "RO49 AAAA 1B31 0075 9384 0000"
    text = f"Kontonummer {iban} wurde belastet."
    assert [(text[s:e], label) for (s, e), label in find(text)] == [(iban, "iban")]


def test_the_model_span_inside_a_verified_one_is_dropped_for_it() -> None:
    """What `supplement` does to the four-digit `national_id` the model returned."""
    text = "Card 4111 1111 1111 1111 expires 09/26."
    model = {(5, 9): ("national_id", 0.98), (33, 38): ("date", 0.95)}
    out = supplement(text, model)
    assert (5, 24) in out and out[(5, 24)] == ("card", 1.0)
    assert (5, 9) not in out, "the mislabelled fragment must not survive alongside it"
    assert out[(33, 38)] == ("date", 0.95), "an unrelated span is untouched"


def test_a_model_span_that_is_only_partly_covered_is_kept_as_well() -> None:
    """Over-redaction is the tolerable direction, so a partial overlap keeps both.

    The engine merges overlapping redaction spans to their outermost extent, so keeping
    both widens a placeholder at worst. Dropping the model's span on a partial overlap
    could leave characters it covered outside every remaining span.
    """
    text = "Nr 4111 1111 1111 1111 gilt."
    # `Nr 4111`, which starts before the card and ends inside it.
    model = {(0, 7): ("national_id", 0.9)}
    out = supplement(text, model)
    assert (3, 22) in out, "the card is found"
    assert (0, 7) in out, "and the partly overlapping span is not dropped for it"


# --------------------------------------------------------------- what is not a card


def test_a_luhn_valid_imei_is_not_reported_as_a_card() -> None:
    """15 digits and Luhn valid, which is the collision the scheme table exists for.

    An IMEI is arguably personal data, but calling one a card number puts a false claim
    in an evidence record, and that is a different kind of error from over-redacting.
    """
    text = "The handset IMEI is 490154203237518 on the account."
    assert find(text) == []


@pytest.mark.parametrize(
    "digits",
    [
        "4111111111111112",  # Luhn fails
        "1234567812345670",  # Luhn passes, no scheme starts 1
        "9999999999999995",  # Luhn passes, no scheme starts 9
        "411111111111111",  # Visa prefix, 15 digits, a length Visa does not issue
    ],
)
def test_a_number_that_is_not_a_card_is_not_reported(digits: str) -> None:
    assert find(f"Reference {digits} on file.") == []


def test_a_date_after_a_card_does_not_swallow_it() -> None:
    """The greedy failure this module was written around.

    `4111 1111 1111 1111 09` is 18 digits in one separated run, and 18 is not a length
    any scheme issues. A single greedy match would test only that and report nothing, so
    every group boundary inside a run is a candidate end.
    """
    text = "Card 4111 1111 1111 1111 09 26"
    assert [text[s:e] for (s, e), _ in find(text)] == ["4111 1111 1111 1111"]


def test_a_card_after_an_unrelated_number_is_still_found() -> None:
    """The same argument at the other end: every group boundary is a candidate start."""
    text = "Ref 99 4111 1111 1111 1111 filed."
    assert [text[s:e] for (s, e), _ in find(text)] == ["4111 1111 1111 1111"]


def test_a_digit_run_too_long_to_be_a_card_is_not_one() -> None:
    text = "Order 41111111111111119926 shipped."
    assert find(text) == []


def test_a_thousands_separated_amount_is_not_a_card() -> None:
    text = "The balance was 1.234.567.890.123.456 before rounding."
    assert find(text) == []


# --------------------------------------------------------------- what is not an IBAN


@pytest.mark.parametrize(
    "value",
    [
        "GB29 NWBK 6016 1331 9268 18",  # mod-97 fails
        "GB29 NWBK 6016 1331 9268",  # a real IBAN clipped short
        "AB12 3456 7890 1234 5678",  # not an IBAN at all
        "DE89",  # the head with nothing after it
    ],
)
def test_a_number_that_is_not_an_iban_is_not_reported(value: str) -> None:
    assert find(f"Please use {value} for the transfer.") == []


def test_an_iban_followed_by_prose_does_not_over_capture() -> None:
    """A run continues across single spaces, so the words after an IBAN are in it.

    Which means the accepted length has to come from mod-97 and a group boundary rather
    than from where the regex stopped.
    """
    iban = "GB29 NWBK 6016 1331 9268 19"
    text = f"Send it to {iban} was the last instruction."
    assert [text[s:e] for (s, e), _ in find(text)] == [iban]


def test_the_digits_inside_an_iban_are_not_reported_as_a_card() -> None:
    """The IBAN pass runs first and its characters are then spoken for."""
    text = "IBAN PL61 1090 1014 0000 0712 1981 2874 was debited."
    assert [label for _, label in find(text)] == ["iban"]


# ------------------------------------------------------------------ all 26 languages

#: One published IBAN per country whose language the library supports, and the sentence
#: it sits in. Every one is verified by mod-97 in the test below rather than trusted,
#: which is also what pins each country's length: a wrong length cannot validate.
PER_LANGUAGE: dict[str, tuple[str, str]] = {
    "bg": ("BG80 BNBG 9661 1020 3456 78", "Плащане по {iban} с карта {card}."),
    "hr": ("HR12 1001 0051 8630 0016 0", "Uplata na {iban} karticom {card}."),
    "cs": ("CZ65 0800 0000 1920 0014 5399", "Platba na {iban} kartou {card}."),
    "da": ("DK50 0040 0440 1162 43", "Betaling til {iban} med kort {card}."),
    "nl": ("NL91 ABNA 0417 1643 00", "Betaling aan {iban} met kaart {card}."),
    "en": ("GB29 NWBK 6016 1331 9268 19", "Payment to {iban} by card {card}."),
    "et": ("EE38 2200 2210 2014 5685", "Makse kontole {iban} kaardiga {card}."),
    "fi": ("FI21 1234 5600 0007 85", "Maksu tilille {iban} kortilla {card}."),
    "fr": ("FR14 2004 1010 0505 0001 3M02 606", "Paiement vers {iban} par {card}."),
    "de": ("DE89 3704 0044 0532 0130 00", "Zahlung an {iban} mit Karte {card}."),
    "el": ("GR16 0110 1250 0000 0001 2300 695", "Πληρωμή σε {iban} με {card}."),
    "hu": ("HU42 1177 3016 1111 1018 0000 0000", "Fizetés a {iban} kártyával {card}."),
    "ga": ("IE29 AIBK 9311 5212 3456 78", "Íocaíocht go {iban} le cárta {card}."),
    "it": ("IT60 X054 2811 1010 0000 0123 456", "Pagamento a {iban} con {card}."),
    "lv": ("LV80 BANK 0000 4351 9500 1", "Maksājums uz {iban} ar karti {card}."),
    "lt": ("LT12 1000 0111 0100 1000", "Mokėjimas į {iban} kortele {card}."),
    "mt": ("MT84 MALT 0110 0001 2345 MTLC AST0 01S", "Ħlas lil {iban} bil {card}."),
    "pl": ("PL61 1090 1014 0000 0712 1981 2874", "Płatność na {iban} kartą {card}."),
    "pt": ("PT50 0002 0123 1234 5678 9015 4", "Pagamento para {iban} com {card}."),
    "ro": ("RO49 AAAA 1B31 0075 9384 0000", "Plata către {iban} cu cardul {card}."),
    "sk": ("SK31 1200 0000 1987 4263 7541", "Platba na {iban} kartou {card}."),
    "sl": ("SI56 2633 0001 2039 086", "Plačilo na {iban} s kartico {card}."),
    "es": ("ES91 2100 0418 4502 0005 1332", "Pago a {iban} con la tarjeta {card}."),
    "sv": ("SE45 5000 0000 0583 9825 7466", "Betalning till {iban} med {card}."),
    "tr": ("TR33 0006 1005 1978 6457 8413 26", "{iban} hesabına {card} ile ödeme."),
    "az": ("AZ21 NABZ 0000 0000 1370 1000 1944", "{iban} hesabına {card} ile ödəniş."),
}


def test_every_supported_language_has_a_case() -> None:
    """English plus five is a bug, per CLAUDE.md. Asserted rather than assumed."""
    assert set(PER_LANGUAGE) == set(LANGUAGES)


@pytest.mark.parametrize("language", sorted(PER_LANGUAGE))
def test_a_card_and_an_iban_are_found_in_every_language(language: str) -> None:
    """Both spans, in one sentence, in each of the 26.

    Nothing here is language-specific, which is exactly the claim being checked: a
    checksum works the same in Greek and in Maltese, and a script with no Latin letters
    around the number must not move a span.
    """
    iban, sentence = PER_LANGUAGE[language]
    card = "5555 5555 5555 4444"
    text = sentence.format(iban=iban, card=card)
    found = {label: text[start:end] for (start, end), label in find(text)}
    assert found == {"iban": iban, "card": card}


# ------------------------------------------------------------------------- the schemes


@pytest.mark.parametrize(
    ("scheme", "number"),
    [
        ("visa-13", "4222 2222 2222 2"),
        ("visa-16", "4111 1111 1111 1111"),
        ("mastercard-5x", "5555 5555 5555 4444"),
        ("mastercard-2x", "2223 0031 2200 3222"),
        ("amex", "3782 822463 10005"),
        ("discover", "6011 1111 1111 1117"),
        ("jcb", "3530 1113 3330 0000"),
        ("diners", "3056 9309 0259 04"),
        ("unionpay", "6200 0000 0000 0005"),
    ],
)
def test_each_scheme_in_the_table_is_recognised(scheme: str, number: str) -> None:
    text = f"Paid with {number} on the {scheme} network."
    assert [text[s:e] for (s, e), label in find(text) if label == "card"] == [number]


# -------------------------------------------------------------------------- the edges


def test_empty_and_entity_free_text_finds_nothing() -> None:
    for text in ("", "   ", "There is no personal data in this sentence at all."):
        assert find(text) == [], text


def test_a_card_and_an_iban_in_one_sentence_are_both_found() -> None:
    text = "Charge 4111 1111 1111 1111 and credit DE89 3704 0044 0532 0130 00 today."
    assert [label for _, label in find(text)] == ["card", "iban"]


def test_both_labels_are_entity_types_the_rest_of_the_detector_knows() -> None:
    """The module cannot import `pii` to check this, because `pii` imports the module.

    Worth a test rather than a comment: a label outside `ENTITY_TYPES` would be filtered
    out by `_wanted_entities` for every policy that names its entities, so the pass
    would run, find the card, and report nothing. That is the silent no-op again,
    arriving through a typo.
    """
    from flowx_border.detectors.pii import ENTITY_TYPES

    assert CARD in ENTITY_TYPES
    assert IBAN in ENTITY_TYPES


def test_supplement_returns_the_input_unchanged_when_there_is_nothing_to_add() -> None:
    """No verified entity means no work and no new object churn on the common path."""
    spans = {(0, 5): ("person", 0.9)}
    assert supplement("Marie went home.", spans) is spans
