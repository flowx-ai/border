# SPDX-License-Identifier: Apache-2.0
"""Tests for the output_format detector.

Sixteen hub validators collapsed into one detector, so the first block below is one
test per validator it replaces: whatever the option is called here, the check the
original performed still happens.

The 26-language block is the part that would not exist in a naive port. Shape checks
look language-neutral and are not, and two of the four failures are only visible outside
English: a length limit counted in code points means two different limits for the same
visible Romanian text, and the obvious way to write a lowercase check passes a string
that is not lowercase in Croatian.
"""

from __future__ import annotations

import unicodedata

import pytest

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.multilingual import LANGUAGES as CLAIMED
from flowx_border.detectors.output_format import (
    DEFAULT_WORDS_PER_MINUTE,
    OutputFormatDetector,
    OutputFormatError,
    graphemes,
)
from flowx_border.types import Finding

DETECTOR = OutputFormatDetector()
CTX = Context()


def run(text: str, **options: object) -> list[Finding]:
    return DETECTOR.run(text, DetectorConfig(on_fail="flag", options=options), CTX)


def labels(text: str, **options: object) -> list[str]:
    return [finding.label for finding in run(text, **options)]


# ------------------------------------------------------- the unconfigured case first


def test_no_options_reports_that_rather_than_a_clean_scan() -> None:
    found = run("anything")
    assert [f.label for f in found] == ["format_not_configured"]
    assert found[0].action == "log"


def test_the_unconfigured_finding_never_blocks() -> None:
    found = DETECTOR.run("x", DetectorConfig(on_fail="block"), CTX)
    assert found[0].action == "log"


def test_a_rate_alone_is_not_a_configuration() -> None:
    # words_per_minute modifies max_reading_seconds; on its own it checks nothing.
    assert labels("anything", words_per_minute=150) == ["format_not_configured"]


def test_an_unknown_option_raises_rather_than_checking_nothing() -> None:
    with pytest.raises(OutputFormatError, match="does not know the option"):
        run("x", maximum_length=10)


# ----------------------------------------------- one test per validator it replaces


def test_valid_json() -> None:
    assert run('{"a": 1}', json=True) == []
    assert labels("not json", json=True) == ["not_json"]


def test_valid_html() -> None:
    assert run("<p>Hello</p>", html=True) == []
    assert labels("<p>Hello", html=True) == ["not_html"]


def test_a_void_element_does_not_count_as_unclosed() -> None:
    assert run("<p>Line<br>break</p>", html=True) == []


def test_has_url_and_valid_url() -> None:
    assert run("See https://example.com now.", url="required") == []
    assert labels("No link here.", url="required") == ["url_missing"]
    assert run("No link here.", url="absent") == []
    assert labels("See https://example.com now.", url="absent") == ["url_present"]


def test_an_unknown_url_mode_raises() -> None:
    with pytest.raises(OutputFormatError, match=r"required.*absent"):
        run("x", url="maybe")


def test_valid_length() -> None:
    assert run("abcde", max_length=5, min_length=5) == []
    assert labels("abcdef", max_length=5) == ["too_long"]
    assert labels("abc", min_length=5) == ["too_short"]


def test_two_words() -> None:
    # two_words is max_words: 2 with min_words: 2.
    assert run("hello world", max_words=2, min_words=2) == []
    assert labels("hello big world", max_words=2) == ["too_many_words"]
    assert labels("hello", min_words=2) == ["too_few_words"]


def test_one_line() -> None:
    assert run("all on one line", one_line=True) == []
    assert labels("two\nlines", one_line=True) == ["not_one_line"]


def test_lowercase_and_uppercase() -> None:
    assert run("all lower", case="lower") == []
    assert labels("Not All Lower", case="lower") == ["wrong_case"]
    assert run("ALL UPPER", case="upper") == []
    assert labels("not all upper", case="upper") == ["wrong_case"]


def test_an_unknown_case_raises() -> None:
    with pytest.raises(OutputFormatError, match=r"lower.*upper"):
        run("x", case="title")


def test_valid_choices() -> None:
    assert run("yes", choices=["yes", "no"]) == []
    assert labels("maybe", choices=["yes", "no"]) == ["not_a_choice"]


def test_a_choice_is_matched_on_folded_text() -> None:
    # So a policy listing `yes` accepts `YES`, and a Romanian choice accepts either
    # spelling of its diacritic.
    assert run("YES", choices=["yes"]) == []
    assert run("informaţie", choices=["informație"]) == []


def test_valid_range() -> None:
    assert run("42", numeric_range=[0, 100]) == []
    assert labels("142", numeric_range=[0, 100]) == ["out_of_range"]
    assert labels("not a number", numeric_range=[0, 100]) == ["not_a_number"]


def test_a_comma_decimal_separator_is_a_number() -> None:
    # Correct in most of the 26 languages, so an output reading "3,5" is a number
    # rather than a parse failure.
    assert run("3,5", numeric_range=[0, 10]) == []


def test_ends_with_and_starts_with() -> None:
    assert run("A sentence.", ends_with=".") == []
    assert labels("A sentence", ends_with=".") == ["wrong_suffix"]
    assert run("INV-2026", starts_with="inv-") == []
    assert labels("REF-2026", starts_with="inv-") == ["wrong_prefix"]


def test_regex_match_and_cucumber_expression() -> None:
    assert run("INV-2026", regex=r"INV-[0-9]+") == []
    assert labels("REF-2026", regex=r"INV-[0-9]+") == ["regex_mismatch"]


def test_a_regex_is_a_full_match_rather_than_a_search() -> None:
    # Otherwise `regex: "yes"` passes for "yes and also no", which is not what a shape
    # assertion means.
    assert labels("INV-2026 and more", regex=r"INV-[0-9]+") == ["regex_mismatch"]


def test_an_uncompilable_regex_raises() -> None:
    with pytest.raises(OutputFormatError, match="does not compile"):
        run("x", regex="[unclosed")


def test_quotes_price_is_expressible_as_a_regex() -> None:
    assert run("The price is 412 EUR", regex=r".*\d+ EUR") == []


def test_reading_time() -> None:
    text = " ".join(["word"] * 400)
    # 400 words at 200 wpm is 120 seconds.
    assert labels(text, max_reading_seconds=60) == ["too_long_to_read"]
    assert run(text, max_reading_seconds=180) == []


def test_the_reading_rate_is_a_policy_option_not_a_constant() -> None:
    """Applying one language's reading rate to 26 is the assumption being avoided.

    Finnish and Hungarian pack far more meaning per word than English does, so the
    upstream validator's hard-coded rate is one language's answer used everywhere.
    """
    assert DEFAULT_WORDS_PER_MINUTE == 200
    text = " ".join(["word"] * 300)
    assert run(text, max_reading_seconds=95) == []
    assert labels(text, max_reading_seconds=95, words_per_minute=100) == [
        "too_long_to_read"
    ]


def test_a_zero_reading_rate_raises_rather_than_dividing_by_zero() -> None:
    with pytest.raises(OutputFormatError, match="above 0"):
        run("x", max_reading_seconds=10, words_per_minute=0)


# ------------------------------------------------------- where 26 languages bite


def test_length_counts_graphemes_not_code_points() -> None:
    """The same visible Romanian text must mean one length, not two.

    Whether a diacritic arrives precomposed or decomposed is a property of the platform
    that produced the text, not of the text, so a limit counted in code points is two
    different limits for one string.
    """
    precomposed = "că"
    decomposed = unicodedata.normalize("NFD", precomposed)
    assert len(precomposed) != len(decomposed)
    assert graphemes(precomposed) == graphemes(decomposed) == 2
    assert run(decomposed, max_length=2) == []
    assert labels(decomposed, max_length=1) == ["too_long"]


def test_a_croatian_digraph_is_not_lowercase() -> None:
    """The failure the obvious implementation has.

    "no character in it is uppercase" passes this string, because the titlecase digraph
    is neither upper nor lower. Croatian is one of the 26.
    """
    titlecase = "ǅ"
    assert not titlecase.isupper()
    assert not any(char.isupper() for char in titlecase)  # the obvious check passes
    assert labels(titlecase, case="lower") == ["wrong_case"]
    assert run("ǆ", case="lower") == []


def test_text_with_no_cased_characters_passes_either_case_check() -> None:
    # A numeric answer is not miscased, and reporting it as both would be absurd.
    assert run("412", case="lower") == []
    assert run("412", case="upper") == []


#: code -> (an ordinary sentence, its grapheme length)
LANGUAGES: dict[str, str] = {
    "en": "Your balance is 412 EUR this morning.",
    "ro": "Soldul dumneavoastră este de 412 EUR în această dimineață.",
    "bg": "Салдото ви е 412 EUR към тази сутрин.",
    "cs": "Váš zůstatek je dnes ráno 412 EUR.",
    "da": "Din saldo er 412 EUR i morges.",
    "de": "Ihr Kontostand beträgt heute Morgen 412 EUR.",
    "el": "Το υπόλοιπό σας είναι 412 EUR σήμερα το πρωί.",
    "es": "Su saldo es de 412 EUR esta mañana.",
    "et": "Teie saldo on täna hommikul 412 EUR.",
    "fi": "Saldosi on tänä aamuna 412 EUR.",
    "fr": "Votre solde est de 412 EUR ce matin.",
    "ga": "Is é 412 EUR an t-iarmhéid atá agat ar maidin.",
    "hr": "Vaš saldo jutros iznosi 412 EUR.",
    "hu": "Az egyenlege ma reggel 412 EUR.",
    "it": "Il suo saldo è di 412 EUR questa mattina.",
    "lt": "Jūsų balansas šį rytą yra 412 EUR.",
    "lv": "Jūsu atlikums šorīt ir 412 EUR.",
    "mt": "Il-bilanċ tiegħek dalgħodu huwa 412 EUR.",
    "nl": "Uw saldo is vanmorgen 412 EUR.",
    "pl": "Twoje saldo wynosi 412 EUR na dziś rano.",
    "pt": "O seu saldo é de 412 EUR esta manhã.",
    "sk": "Váš zostatok je dnes ráno 412 EUR.",
    "sl": "Vaše stanje je danes zjutraj 412 EUR.",
    "sv": "Ditt saldo är 412 EUR i morse.",
    "tr": "Bakiyeniz bu sabah itibarıyla 412 EUR.",
    "az": "Bu səhər hesabınızdaki qalıq 412 EUR-dur.",
}


def test_the_fixtures_cover_every_language_the_project_claims() -> None:
    assert set(LANGUAGES) == CLAIMED


@pytest.mark.parametrize("code", sorted(LANGUAGES))
def test_a_length_limit_means_the_same_in_each_language(code: str) -> None:
    """Precomposed and decomposed spellings must not be two different lengths.

    Nine of the 26 carry diacritics that decompose, so this is not a corner case, it is
    most of the supported set.
    """
    text = LANGUAGES[code]
    decomposed = unicodedata.normalize("NFD", text)
    assert graphemes(text) == graphemes(decomposed), code
    limit = graphemes(text)
    assert run(text, max_length=limit) == [], code
    assert run(decomposed, max_length=limit) == [], code


@pytest.mark.parametrize("code", sorted(LANGUAGES))
def test_a_word_count_works_in_each_language(code: str) -> None:
    text = LANGUAGES[code]
    assert run(text, min_words=1, max_words=len(text.split())) == [], code


@pytest.mark.parametrize("code", sorted(LANGUAGES))
def test_an_ordinary_sentence_in_each_language_is_one_line_and_has_no_url(
    code: str,
) -> None:
    assert run(LANGUAGES[code], one_line=True, url="absent") == [], code


# --------------------------------------------------------------------------- plumbing


def test_several_failures_are_reported_separately() -> None:
    # One finding per broken assertion, so a record says which ones failed rather than
    # only that something did.
    found = labels("two\nlines", one_line=True, max_length=3, json=True)
    assert set(found) == {"not_one_line", "too_long", "not_json"}


def test_no_finding_carries_a_span() -> None:
    # These are assertions about the whole output. Pointing at one offset would imply a
    # place to fix, which a shape check cannot know.
    for finding in run("nope", json=True):
        assert finding.span is None


def test_the_detector_matches_the_catalogue() -> None:
    from flowx_border.detectors.catalogue import CATALOGUE

    spec = CATALOGUE["output_format"]
    assert (DETECTOR.id, DETECTOR.tier) == ("output_format", spec.tier)
    assert DETECTOR.sides == spec.sides


def test_warm_is_idempotent() -> None:
    DETECTOR.warm()
    DETECTOR.warm()
    assert run('{"a": 1}', json=True) == []


def test_findings_never_carry_the_text() -> None:
    for finding in run("balance 412 EUR", json=True):
        assert "412" not in finding.model_dump_json()
