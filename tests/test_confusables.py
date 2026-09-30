# SPDX-License-Identifier: Apache-2.0
"""Tests for the confusables detector.

The attacks are the easy half: a Cyrillic `а` in `acme`, a hostname with one borrowed
letter, `rn` for `m`. The half that decides whether this can be on by default is the
other one: Greek and Bulgarian are written in scripts full of letters that look Latin,
Turkish and Azerbaijani have a dotless i that UTS #39 folds onto i, and Bulgarian hangs
Cyrillic suffixes off Latin loanwords. Every language gets a clean sentence that must
produce nothing and the same sentence with a lookalike in it that must be found.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.catalogue import CATALOGUE
from flowx_border.detectors.confusables import (
    EXEMPT,
    ConfusablesDetector,
    ConfusablesError,
    lookalikes,
    mixed_script,
    tables,
)
from flowx_border.detectors.multilingual import LANGUAGES as CLAIMED
from flowx_border.types import Finding

DETECTOR = ConfusablesDetector()
CTX = Context()
DATA = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "flowx_border"
    / "data"
    / "confusables.json"
)

#: A Cyrillic а followed by Latin `cme`. Renders as `acme` everywhere.
SPOOF = "аcme"
TERMS = ["acme", "acme.com"]


def run(text: str, **options: object) -> list[Finding]:
    return DETECTOR.run(text, DetectorConfig(on_fail="flag", options=options), CTX)


def labels(text: str, **options: object) -> list[str]:
    return [finding.label for finding in run(text, **options)]


#: One ordinary sentence per language, each naming Acme the honest way and each written
#: with the letters that language actually uses. Greek and Bulgarian carry Latin brand
#: names beside native words, which is how both are written in practice.
CLEAN = {
    "bg": "Моля, изпратете ми извлечението от Acme за септември в PDF-а.",
    "hr": "Molim vas, pošaljite mi izvod iz Acme za rujan. Hvala, Đurđica.",
    "cs": "Prosím, pošlete mi výpis od Acme za září. Děkuji, Řehoř.",
    "da": "Send venligst kontoudtoget fra Acme for september. Tak, Søren Ærø.",
    "nl": "Stuur me alstublieft het overzicht van Acme voor september. Dank, Eline.",
    "en": "Please send me the Acme statement for September. Thanks, Ian.",
    "es": "Envíeme el extracto de Acme de septiembre, por favor. Gracias, Íñigo.",
    "sv": "Skicka kontoutdraget från Acme för september. Tack, Åsa Öberg.",
    "tr": "Lütfen Acme'nin eylül ekstresini gönderin. Işık sık sık İstanbul'a gider.",
    "et": "Palun saatke mulle Acme septembri väljavõte. Aitäh, Õie Šõkin.",
    "fi": "Lähettäkää minulle Acme:n syyskuun tiliote. Kiitos, Äijä.",
    "fr": "Envoyez-moi le relevé Acme de septembre, s'il vous plaît. Merci, Anaïs.",
    "de": "Bitte senden Sie mir den Acme-Auszug für September. Grüße, Jürgen Straße.",
    "el": "Παρακαλώ στείλτε μου την κατάσταση της Acme για τον Σεπτέμβριο. ΑΤΜ, ΕΕ.",
    "hu": "Kérem, küldje el az Acme szeptemberi kivonatát. Köszönöm, Ősz Győző.",
    "ga": "Seol chugam ráiteas Acme do Mheán Fómhair, le do thoil. Go raibh maith.",
    "it": "Mi invii l'estratto conto Acme di settembre, per favore. Grazie, Niccolò.",
    "lt": "Prašau atsiųsti Acme rugsėjo išrašą. Ačiū, Žydrūnė.",
    "lv": "Lūdzu, nosūtiet man Acme septembra izrakstu. Paldies, Ķēniņš.",
    "mt": "Jekk jogħġbok ibgħatli l-istqarrija ta' Acme għal Settembru. Grazzi, Ħażna.",
    "pl": "Proszę przesłać mi wyciąg Acme za wrzesień. Dziękuję, Łukasz Żółć.",
    "pt": "Envie-me o extrato da Acme de setembro, por favor. Obrigado, João.",
    "ro": "Vă rog să îmi trimiteți extrasul Acme pentru septembrie. Mulțumesc, Ştefan.",
    "sk": "Pošlite mi, prosím, výpis Acme za september. Ďakujem, Ľubomír.",
    "sl": "Prosim, pošljite mi izpisek Acme za september. Hvala, Živa.",
    "az": "Zəhmət olmasa, Acme-nin sentyabr çıxarışını göndərin. Sağ olun, İlqar.",
}


# ------------------------------------------------------------------------ the attacks


def test_a_cyrillic_letter_in_a_listed_term_is_a_lookalike() -> None:
    assert labels(SPOOF, terms=TERMS) == ["lookalike_term", "mixed_script"]


def test_the_span_covers_the_lookalike_and_nothing_else() -> None:
    text = f"Contact {SPOOF} support."
    spans = {f.span for f in run(text, terms=TERMS)}
    assert spans == {(8, 12)}
    assert text[8:12] == SPOOF


def test_a_term_spelled_entirely_in_cyrillic_capitals_is_found() -> None:
    # Whole-script: no Latin letter at all, so mixed_script cannot see it and only the
    # term list can.
    assert labels("АСМЕ", terms=TERMS) == ["lookalike_term"]


def test_a_lowercase_cyrillic_i_is_found() -> None:
    # Cyrillic і folds to i only after case folding, the other key.
    assert "lookalike_term" in labels("vіsa", terms=["visa"])
    assert "lookalike_term" in labels("VІSA", terms=["visa"])


def test_ascii_lookalikes_are_found_without_any_foreign_script() -> None:
    assert labels("acrne", terms=TERMS) == ["lookalike_term"]
    assert labels("paypa1", terms=["paypal"]) == ["lookalike_term"]
    assert labels("PayPaI", terms=["paypal"]) == ["lookalike_term"]


def test_a_zero_width_character_does_not_hide_a_lookalike() -> None:
    text = "ac​mе"
    assert "lookalike_term" in labels(text, terms=TERMS)
    assert run(text, terms=TERMS)[0].span == (0, len(text))


def test_a_lookalike_hostname_is_found_under_a_subdomain() -> None:
    text = f"Log in at https://login.{SPOOF}.com/verify now."
    spans = [f.span for f in run(text, terms=TERMS) if f.label == "lookalike_term"]
    assert spans
    start, end = spans[0]
    assert text[start:end] == f"{SPOOF}.com"


def test_a_multi_word_term_matches_across_collapsed_whitespace() -> None:
    assert "lookalike_term" in labels(f"{SPOOF}   Bank", terms=["Acme Bank"])


@pytest.mark.parametrize("code", sorted(CLEAN))
def test_a_lookalike_inside_each_language_is_found(code: str) -> None:
    text = CLEAN[code].replace("Acme", SPOOF.capitalize(), 1)
    assert SPOOF.capitalize() in text
    found = labels(text, terms=TERMS)
    assert "lookalike_term" in found, code
    assert "mixed_script" in found, code


@pytest.mark.parametrize("code", sorted(CLEAN))
def test_a_mixed_script_word_inside_each_language_is_found_without_terms(
    code: str,
) -> None:
    text = f"{CLEAN[code]} pаypal"
    assert labels(text) == ["mixed_script"], code


# --------------------------------------------------------------- the false positives


def test_the_fixtures_cover_every_language_the_project_claims() -> None:
    assert set(CLEAN) == CLAIMED


@pytest.mark.parametrize("code", sorted(CLEAN))
def test_ordinary_text_in_each_language_produces_nothing(code: str) -> None:
    """With the term list set, so both halves are running."""
    assert run(CLEAN[code], terms=TERMS) == [], f"{code}: {CLEAN[code]!r}"


def test_an_exact_match_is_left_to_banned_terms() -> None:
    assert run("ACME and acme and Acme", terms=TERMS) == []


def test_the_dotless_i_is_not_a_disguise_of_i() -> None:
    # `sık` is frequent, `sik` is the word a Turkish term list carries. UTS #39 folds
    # one onto the other; this detector must not.
    assert run("Bu sık olur.", terms=["sik"]) == []
    assert "ı" in EXEMPT


def test_greek_and_bulgarian_words_are_one_script() -> None:
    for word in ("Χαίρετε", "ΑΤΜ", "ΟΠΑΠ", "Здравейте", "САЩ", "ЕООД"):
        assert mixed_script(word) == [], word


def test_a_hyphen_separates_scripts() -> None:
    for word in ("PDF-а", "SMS-ите", "β-каротин", "α-helix", "γ-GT"):
        assert mixed_script(word) == [], word


def test_a_japanese_name_is_not_mixed_script() -> None:
    assert mixed_script("東京タワーとさくら") == []


def test_a_foreign_letter_that_passes_for_nothing_is_not_reported() -> None:
    # A Greek mu in front of a Latin g is two scripts, and neither letter renders as a
    # letter of the other. Unit notation, not a disguise.
    assert mixed_script("μg") == []


def test_a_latin_letter_in_a_bulgarian_word_is_found() -> None:
    # The keyboard-layout slip and the deliberate spoof look the same, and both are a
    # word a reader would take for one they are not.
    assert mixed_script("cъм") == [(0, 3)]


# --------------------------------------------------------------------------- plumbing


def test_nothing_configured_says_so() -> None:
    findings = run("anything", mixed_script=False)
    assert [f.label for f in findings] == ["terms_not_configured"]
    assert findings[0].action == "log"


def test_mixed_script_can_be_switched_off() -> None:
    assert labels(SPOOF, terms=TERMS, mixed_script=False) == ["lookalike_term"]


def test_bad_options_are_refused() -> None:
    with pytest.raises(ConfusablesError):
        run("x", terms=42)
    with pytest.raises(ConfusablesError):
        run("x", mixed_script="yes")


def test_the_action_comes_from_the_policy() -> None:
    findings = DETECTOR.run(
        SPOOF, DetectorConfig(on_fail="block", options={"terms": TERMS}), CTX
    )
    assert {f.action for f in findings} == {"block"}


def test_lookalikes_is_empty_without_terms() -> None:
    assert lookalikes(SPOOF, []) == []


def test_the_data_records_its_unicode_sources() -> None:
    raw = json.loads(DATA.read_text(encoding="utf-8"))
    for source in ("confusables", "scripts"):
        entry = raw[source]
        assert entry["source"].startswith("https://www.unicode.org/Public/")
        assert entry["version"] == "18.0.0"
        assert len(entry["sha256"]) == 64
    assert raw["map"]["а"] == "a"


def test_the_exemptions_are_applied() -> None:
    for char in EXEMPT:
        assert char not in tables().map


def test_it_is_catalogued_and_registered() -> None:
    from flowx_border.registry import implemented_detectors

    spec = CATALOGUE["confusables"]
    assert spec.tier == "T1"
    assert spec.sides == frozenset({"input", "output"})
    assert not spec.requires
    assert "confusables" in implemented_detectors()
