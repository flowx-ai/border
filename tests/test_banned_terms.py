# SPDX-License-Identifier: Apache-2.0
"""Tests for the banned_terms detector.

The 26-language sweep is the substance of the file. A term list detector that works in
English is the thing this port was supposed to replace, so a fixture set covering one
script would leave the claim untested. Each language contributes a term, a sentence
containing it, and a sentence that does not, and the term is capitalised differently in
the sentence than in the list wherever the language allows, so casefolding is exercised
in every script rather than only in Latin.
"""

from __future__ import annotations

import pytest

from flowx_border.detectors.banned_terms import BannedTermsDetector, BannedTermsError
from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.multilingual import LANGUAGES as CLAIMED
from flowx_border.types import Finding

DETECTOR = BannedTermsDetector()
CTX = Context()


def cfg(**options: object) -> DetectorConfig:
    return DetectorConfig(on_fail="flag", options=options)


def run(text: str, **options: object) -> list[Finding]:
    return DETECTOR.run(text, cfg(**options), CTX)


def labels(text: str, **options: object) -> list[str]:
    return [finding.label for finding in run(text, **options)]


# ------------------------------------------------------- the unconfigured case first


def test_no_terms_reports_that_rather_than_a_clean_scan() -> None:
    """The failure mode this project refuses everywhere: a check that quietly did not
    happen looks exactly like a check that found nothing."""
    found = run("Anything at all.")
    assert [f.label for f in found] == ["terms_not_configured"]
    assert found[0].action == "log"
    assert found[0].span is None


def test_the_unconfigured_finding_never_blocks() -> None:
    # An empty list is a gap in the policy, not a finding about the text.
    found = DETECTOR.run("text", DetectorConfig(on_fail="block"), CTX)
    assert found[0].action == "log"


def test_a_blank_term_list_counts_as_no_terms() -> None:
    assert labels("Anything.", terms=["", "   "]) == ["terms_not_configured"]


# --------------------------------------------------------------------- basic matching


def test_a_listed_term_is_found() -> None:
    assert labels("Our competitor announced a price.", terms=["competitor"]) == [
        "banned_term"
    ]


def test_an_unlisted_term_is_not_found() -> None:
    assert run("Our team announced a price.", terms=["competitor"]) == []


def test_a_single_string_is_accepted_as_well_as_a_list() -> None:
    assert labels("Our competitor is here.", terms="competitor") == ["banned_term"]


def test_every_occurrence_is_reported() -> None:
    text = "Acme and Acme again."
    assert labels(text, terms=["acme"]) == ["banned_term", "banned_term"]


def test_the_span_indexes_the_original_text() -> None:
    # The upstream index map is off by one, which redacts the wrong characters.
    text = "We compete with Acme Corp daily."
    finding = run(text, terms=["acme corp"])[0]
    assert finding.span is not None
    assert text[slice(*finding.span)] == "Acme Corp"


def test_the_span_survives_a_case_and_encoding_difference() -> None:
    text = "Ne vedem la BUCUREŞTI mâine."
    finding = run(text, terms=["bucurești"])[0]
    assert finding.span is not None
    assert text[slice(*finding.span)] == "BUCUREŞTI"


def test_a_term_split_by_a_zero_width_character_is_still_found() -> None:
    text = "Contact ac​me today."
    finding = run(text, terms=["acme"])[0]
    assert finding.span is not None
    # The span covers the zero-width character, so a redaction takes the whole run and
    # the term cannot reassemble in whatever reads the redacted text next.
    assert text[slice(*finding.span)] == "ac​me"


# ------------------------------------------------------------------------- options


def test_whole_words_is_on_by_default() -> None:
    assert run("The data is sparse this quarter.", terms=["arse"]) == []


def test_substring_matching_has_to_be_asked_for() -> None:
    assert labels(
        "The data is sparse this quarter.", terms=["arse"], whole_words=False
    ) == ["banned_term"]


def test_diacritic_folding_is_off_by_default() -> None:
    assert run("O sarbatoare frumoasa.", terms=["sărbătoare"]) == []


def test_diacritic_folding_can_be_switched_on() -> None:
    assert labels(
        "O sarbatoare frumoasa.", terms=["sărbătoare"], fold_diacritics=True
    ) == ["banned_term"]


def test_a_policy_can_name_the_list_so_the_record_says_which_one() -> None:
    # One deployment runs a competitor list and a profanity list. An evidence record
    # that called both `banned_term` would not let an auditor tell them apart.
    assert (
        labels("Our competitor is here.", terms=["competitor"], label="competitor")[0]
        == "competitor"
    )


def test_an_invalid_label_raises_rather_than_being_rewritten() -> None:
    # Silently rewriting it would put a different string in the audit trail than the
    # one the policy author wrote.
    with pytest.raises(BannedTermsError, match="not a valid identifier"):
        run("text", terms=["x"], label="Competitor Names")


def test_a_finding_below_the_threshold_is_still_reported() -> None:
    # Score is 1.0 by design: a term appears or it does not, and there is no model here
    # to be uncertain. A threshold has nothing to bite on, which is the honest outcome.
    found = DETECTOR.run(
        "Our competitor is here.",
        DetectorConfig(
            on_fail="flag", threshold=1.0, options={"terms": ["competitor"]}
        ),
        CTX,
    )
    assert [f.score for f in found] == [1.0]


# --------------------------------------------------------------------- all 26 languages

#: code -> (term as the policy would write it, sentence containing it, sentence without)
LANGUAGES: dict[str, tuple[str, str, str]] = {
    "bg": (
        "конкурент",
        "Нашият конкурент обяви нова цена.",
        "Нашият екип обяви нова цена.",
    ),
    "cs": (
        "konkurence",
        "Naše konkurence oznámila novou cenu.",
        "Náš tým oznámil novou cenu.",
    ),
    "da": (
        "konkurrent",
        "Vores konkurrent annoncerede en ny pris.",
        "Vores team annoncerede en ny pris.",
    ),
    "de": (
        "wettbewerber",
        "Unser Wettbewerber hat einen neuen Preis genannt.",
        "Unser Team hat einen neuen Preis genannt.",
    ),
    "el": (
        "ανταγωνιστής",
        "Ο ανταγωνιστής μας ανακοίνωσε νέα τιμή.",
        "Η ομάδα μας ανακοίνωσε νέα τιμή.",
    ),
    "en": (
        "competitor",
        "Our competitor announced a new price.",
        "Our team announced a new price.",
    ),
    "es": (
        "competidor",
        "Nuestro competidor anunció un nuevo precio.",
        "Nuestro equipo anunció un nuevo precio.",
    ),
    "et": (
        "konkurent",
        "Meie konkurent teatas uue hinna.",
        "Meie meeskond teatas uue hinna.",
    ),
    "fi": (
        "kilpailija",
        "Kilpailija ilmoitti uuden hinnan.",
        "Tiimimme ilmoitti uuden hinnan.",
    ),
    "fr": (
        "concurrent",
        "Notre concurrent a annoncé un nouveau prix.",
        "Notre équipe a annoncé un nouveau prix.",
    ),
    "ga": (
        "iomaitheoir",
        "D'fhógair an iomaitheoir praghas nua.",
        "D'fhógair an fhoireann praghas nua.",
    ),
    "hr": (
        "konkurent",
        "Naš konkurent objavio je novu cijenu.",
        "Naš tim objavio je novu cijenu.",
    ),
    "hu": (
        "versenytárs",
        "A versenytárs új árat jelentett be.",
        "A csapatunk új árat jelentett be.",
    ),
    "it": (
        "concorrente",
        "Il nostro concorrente ha annunciato un nuovo prezzo.",
        "Il nostro team ha annunciato un nuovo prezzo.",
    ),
    "lt": (
        "konkurentas",
        "Mūsų konkurentas paskelbė naują kainą.",
        "Mūsų komanda paskelbė naują kainą.",
    ),
    "lv": (
        "konkurents",
        "Mūsu konkurents paziņoja jaunu cenu.",
        "Mūsu komanda paziņoja jaunu cenu.",
    ),
    "mt": (
        "kompetitur",
        "Il-kompetitur tagħna ħabbar prezz ġdid.",
        "It-tim tagħna ħabbar prezz ġdid.",
    ),
    "nl": (
        "concurrent",
        "Onze concurrent kondigde een nieuwe prijs aan.",
        "Ons team kondigde een nieuwe prijs aan.",
    ),
    "pl": (
        "konkurent",
        "Nasz konkurent ogłosił nową cenę.",
        "Nasz zespół ogłosił nową cenę.",
    ),
    "pt": (
        "concorrente",
        "O nosso concorrente anunciou um novo preço.",
        "A nossa equipa anunciou um novo preço.",
    ),
    "ro": (
        "concurent",
        "Un concurent a anunțat un preț nou.",
        "Echipa noastră a anunțat un preț nou.",
    ),
    "sk": (
        "konkurent",
        "Náš konkurent oznámil novú cenu.",
        "Náš tím oznámil novú cenu.",
    ),
    "sl": (
        "konkurent",
        "Naš konkurent je objavil novo ceno.",
        "Naša ekipa je objavila novo ceno.",
    ),
    "sv": (
        "konkurrent",
        "Vår konkurrent meddelade ett nytt pris.",
        "Vårt team meddelade ett nytt pris.",
    ),
    "tr": (
        "rakip",
        "Rakip firma yeni bir fiyat açıkladı.",
        "Ekibimiz yeni bir fiyat açıkladı.",
    ),
    "az": (
        "rəqib",
        "Rəqib şirkət yeni qiymət elan etdi.",
        "Komandamız yeni qiymət elan etdi.",
    ),
}


def test_the_fixtures_cover_every_language_the_project_claims() -> None:
    assert set(LANGUAGES) == CLAIMED


@pytest.mark.parametrize("code", sorted(LANGUAGES))
def test_a_term_in_each_language_is_found(code: str) -> None:
    term, positive, _ = LANGUAGES[code]
    assert labels(positive, terms=[term]) == ["banned_term"], code


@pytest.mark.parametrize("code", sorted(LANGUAGES))
def test_an_ordinary_sentence_in_each_language_is_clean(code: str) -> None:
    term, _, negative = LANGUAGES[code]
    assert run(negative, terms=[term]) == [], code


@pytest.mark.parametrize("code", sorted(LANGUAGES))
def test_the_span_is_exact_in_each_language(code: str) -> None:
    """The assertion that a Latin-only fixture set cannot make.

    Folding changes length differently in different scripts, so a span that is right in
    English can be wrong by several characters in Greek or Turkish. The engine redacts
    spans without checking them.
    """
    term, positive, _ = LANGUAGES[code]
    finding = run(positive, terms=[term])[0]
    assert finding.span is not None
    assert positive[slice(*finding.span)].casefold() == term.casefold(), code


@pytest.mark.parametrize("code", sorted(LANGUAGES))
def test_an_uppercase_spelling_matches_in_each_language(code: str) -> None:
    term, positive, _ = LANGUAGES[code]
    assert labels(positive.upper(), terms=[term]) == ["banned_term"], code


# --------------------------------------------------------------------------- plumbing


def test_the_detector_matches_the_catalogue() -> None:
    from flowx_border.detectors.catalogue import CATALOGUE

    spec = CATALOGUE["banned_terms"]
    assert (DETECTOR.id, DETECTOR.tier) == ("banned_terms", spec.tier)
    assert DETECTOR.sides == spec.sides


def test_warm_is_idempotent() -> None:
    DETECTOR.warm()
    DETECTOR.warm()
    assert labels("Our competitor is here.", terms=["competitor"]) == ["banned_term"]


def test_findings_never_carry_the_text() -> None:
    for finding in run("Acme owes 412 EUR.", terms=["acme"]):
        assert "412" not in finding.model_dump_json()
        assert "Acme" not in finding.model_dump_json()
