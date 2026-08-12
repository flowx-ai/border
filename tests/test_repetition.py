# SPDX-License-Identifier: Apache-2.0
"""Tests for the repetition detector.

The sweep that matters is the 26-language one, and it tests something easy to miss: a
detector that cannot split a paragraph into sentences never sees two sentences and so
never reports a repeat. That failure is silent, and it is what happens in Greek to a
splitter that knows only ASCII punctuation.
"""

from __future__ import annotations

import pytest

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.multilingual import LANGUAGES as CLAIMED
from flowx_border.detectors.repetition import RepetitionDetector, RepetitionError
from flowx_border.types import Finding

DETECTOR = RepetitionDetector()
CTX = Context()

#: The Greek question mark, U+037E. It is not the semicolon it looks exactly like, and
#: writing it as an escape is the only way to be sure which one is in the file.
GREEK_QUESTION_MARK = "\u037e"


def run(text: str, **options: object) -> list[Finding]:
    return DETECTOR.run(text, DetectorConfig(on_fail="flag", options=options), CTX)


def labels(text: str, **options: object) -> list[str]:
    return [finding.label for finding in run(text, **options)]


def three(first: str, middle: str) -> str:
    """`first`, then something else, then `first` again."""
    return f"{first} {middle} {first}"


BALANCE = "Your balance is 412 EUR today."
BRANCH = "The branch opens at nine in the morning."


def test_an_exact_repeat_is_reported() -> None:
    assert labels(three(BALANCE, BRANCH)) == ["repeated_sentence"]


def test_the_finding_is_on_the_later_sentence() -> None:
    # That is the one to remove. Reporting the first would ask a caller to delete the
    # sentence that introduced the point.
    text = three(BALANCE, BRANCH)
    finding = run(text)[0]
    assert finding.span is not None
    assert finding.span[0] > text.index(BRANCH)


def test_a_near_repeat_is_reported() -> None:
    text = f"{BALANCE} {BRANCH} Your balance is 412 EUR toda."
    assert labels(text) == ["repeated_sentence"]


def test_the_threshold_is_a_policy_option() -> None:
    text = f"{BALANCE} {BRANCH} The payment lands within three working days."
    assert run(text) == []
    assert labels(text, similarity=0.4) == ["repeated_sentence"]


def test_distinct_sentences_are_clean() -> None:
    text = f"{BALANCE} {BRANCH} Transfers take two working days to arrive."
    assert run(text) == []


def test_short_sentences_repeat_legitimately() -> None:
    # "Yes." and "Of course." repeat in every language here, and a detector that
    # reported them would fire hardest on the most polite answers.
    assert run("Yes. Of course. Yes. Of course.") == []


def test_the_minimum_length_is_a_policy_option() -> None:
    assert labels("Yes indeed. Yes indeed.", min_words=2) == ["repeated_sentence"]


def test_three_identical_sentences_are_two_repeats_not_three_findings() -> None:
    # A sentence already reported as a repeat is not evidence that the next one is.
    assert labels(f"{BALANCE} " * 3) == ["repeated_sentence", "repeated_sentence"]


def test_case_and_diacritic_spelling_do_not_hide_a_repeat() -> None:
    # Compared over folded text: the Romanian cedilla and comma spellings are one word.
    original = "Informația din contul dumneavoastră este corectă."
    text = f"{original} Altceva cu totul aici acum. {original.upper()}"
    assert labels(text) == ["repeated_sentence"]


def test_a_zero_width_character_does_not_hide_a_repeat() -> None:
    hidden = BALANCE.replace("balance", "bal\u200bance")
    assert labels(f"{BALANCE} {BRANCH} {hidden}") == ["repeated_sentence"]


def test_a_long_document_says_the_comparison_was_partial() -> None:
    """Quadratic in the number of sentences, so it is bounded and says when it stopped.

    Reporting nothing for the sentences it did not reach would be indistinguishable
    from reporting that they were fine.
    """
    text = " ".join(f"This is sentence number {n} of very many." for n in range(50))
    found = labels(text, max_sentences=10)
    assert "comparison_incomplete" in found
    assert run(text, max_sentences=10)[0].action == "log"


def test_a_zero_threshold_raises_rather_than_reporting_everything() -> None:
    with pytest.raises(RepetitionError, match="above 0"):
        run(three(BALANCE, BRANCH), similarity=0)


def test_an_empty_output_is_not_an_error() -> None:
    assert run("") == []


#: language -> (a sentence that gets repeated, a different sentence between the two).
#: The point is the sentence splitter: if it cannot divide the text there is one
#: sentence and nothing to compare, and the result looks exactly like an answer that
#: did not repeat itself.
REPEATS: dict[str, tuple[str, str]] = {
    "en": (
        "Your balance is 412 EUR today.",
        "The branch opens at nine.",
    ),
    "ro": (
        "Soldul este de 412 EUR astăzi.",
        "Sucursala se deschide la nouă.",
    ),
    "bg": (
        "Салдото ви е 412 EUR днес.",
        "Клонът отваря в девет.",
    ),
    "cs": (
        "Váš zůstatek je dnes 412 EUR.",
        "Pobočka otevírá v devět.",
    ),
    "da": (
        "Din saldo er 412 EUR i dag.",
        "Filialen åbner klokken ni.",
    ),
    "de": (
        "Ihr Kontostand beträgt heute 412 EUR.",
        "Die Filiale öffnet um neun.",
    ),
    "el": (
        "Το υπόλοιπό σας είναι 412 EUR σήμερα.",
        "Το κατάστημα ανοίγει στις εννέα.",
    ),
    "es": (
        "Su saldo es de 412 EUR hoy.",
        "La sucursal abre a las nueve.",
    ),
    "et": (
        "Teie saldo on täna 412 EUR.",
        "Kontor avatakse kell üheksa.",
    ),
    "fi": (
        "Saldosi on tänään 412 EUR.",
        "Konttori avautuu yhdeksältä.",
    ),
    "fr": (
        "Votre solde est de 412 EUR aujourd'hui.",
        "L'agence ouvre à neuf heures.",
    ),
    "ga": (
        "Is é 412 EUR an t-iarmhéid inniu.",
        "Osclaíonn an brainse ar a naoi.",
    ),
    "hr": (
        "Vaš saldo danas iznosi 412 EUR.",
        "Poslovnica se otvara u devet.",
    ),
    "hu": (
        "Az egyenlege ma 412 EUR.",
        "A fiók kilenckor nyit ki.",
    ),
    "it": (
        "Il suo saldo oggi è di 412 EUR.",
        "La filiale apre alle nove.",
    ),
    "lt": (
        "Jūsų balansas šiandien yra 412 EUR.",
        "Skyrius atidaromas devintą.",
    ),
    "lv": (
        "Jūsu atlikums šodien ir 412 EUR.",
        "Filiāle atveras deviņos.",
    ),
    "mt": (
        "Il-bilanċ tiegħek illum huwa 412 EUR.",
        "Il-fergħa tiftaħ fid-disgħa.",
    ),
    "nl": (
        "Uw saldo is vandaag 412 EUR.",
        "Het kantoor opent om negen uur.",
    ),
    "pl": (
        "Twoje saldo wynosi dziś 412 EUR.",
        "Oddział otwiera się o dziewiątej.",
    ),
    "pt": (
        "O seu saldo hoje é de 412 EUR.",
        "A agência abre às nove.",
    ),
    "sk": (
        "Váš zostatok je dnes 412 EUR.",
        "Pobočka otvára o deviatej.",
    ),
    "sl": (
        "Vaše stanje je danes 412 EUR.",
        "Poslovalnica se odpre ob devetih.",
    ),
    "sv": (
        "Ditt saldo är 412 EUR i dag.",
        "Kontoret öppnar klockan nio.",
    ),
    "tr": (
        "Bakiyeniz bugün 412 EUR.",
        "Şube dokuzda açılıyor.",
    ),
    "az": (
        "Bu gün qalığınız 412 EUR-dur.",
        "Filial doqquzda açılır.",
    ),
}


def test_the_fixtures_cover_every_language_the_project_claims() -> None:
    assert set(REPEATS) == CLAIMED


@pytest.mark.parametrize("code", sorted(REPEATS))
def test_a_repeat_in_each_language_is_found(code: str) -> None:
    repeated, other = REPEATS[code]
    assert labels(three(repeated, other)) == ["repeated_sentence"], code


@pytest.mark.parametrize("code", sorted(REPEATS))
def test_the_same_text_without_the_repeat_is_clean(code: str) -> None:
    # Which is what gives the test above its meaning: the detector is reacting to the
    # repetition rather than to something else in the sentence.
    repeated, other = REPEATS[code]
    assert run(f"{repeated} {other}") == [], code


def test_the_greek_question_mark_splits_a_sentence() -> None:
    """U+037E is not a semicolon, though nothing about it looks different.

    A splitter that knew only ASCII punctuation would read this as one sentence and
    report no repeat, which is the silent failure the sweep above exists to catch.
    """
    question = f"Θέλετε βοήθεια με τον λογαριασμό σας{GREEK_QUESTION_MARK}"
    text = f"{question} Ναι βεβαίως μπορώ να βοηθήσω τώρα. {question}"
    assert labels(text) == ["repeated_sentence"]


def test_an_ascii_semicolon_does_not_split_a_sentence() -> None:
    # It joins clauses in every language here, so treating it as a terminator would
    # split one sentence into two and change what any per-sentence measure means.
    from flowx_border.detectors.multilingual import sentences

    assert len(sentences("One clause; another clause.")) == 1


def test_the_detector_matches_the_catalogue() -> None:
    from flowx_border.detectors.catalogue import CATALOGUE, CORE

    spec = CATALOGUE["repetition"]
    assert (DETECTOR.id, DETECTOR.tier) == ("repetition", spec.tier)
    assert DETECTOR.sides == spec.sides
    # No dependency, because difflib replaces the two that upstream uses.
    assert "repetition" in CORE


def test_findings_never_carry_the_text() -> None:
    for finding in run(three(BALANCE, BRANCH)):
        assert "412" not in finding.model_dump_json()
