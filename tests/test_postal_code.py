# SPDX-License-Identifier: Apache-2.0
"""Tests for the postal_code detector.

Three sweeps, and the first two are the ones that decide whether this is usable.

**Every country's own example is accepted.** The data file carries an example postcode
per country precisely so this can be asserted: a pattern that rejects the country's own
example is a typo, and there are 29 chances to make one.

**Ordinary numbers are not postcodes.** Prices, years and house numbers are the same
shape as a postcode in several countries, and a detector that reported them would be
switched off. This is why a cue is required, and the negative fixtures are what keep the
cue logic honest.

**Compound street names.** In the Germanic and Nordic languages the street word is the
tail of one word, `Herengracht`, not a word of its own. A whole-word cue matches none of
them, so those languages get their own sweep.
"""

from __future__ import annotations

import pytest

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.postal_code import (
    PostalCodeDataError,
    PostalCodeDetector,
    load_countries,
    load_cues,
    load_suffix_cues,
    unreviewed_countries,
)
from flowx_border.types import Finding

DETECTOR = PostalCodeDetector()
CTX = Context()


def run(text: str, **options: object) -> list[Finding]:
    return DETECTOR.run(text, DetectorConfig(on_fail="flag", options=options), CTX)


def labels(text: str, **options: object) -> list[str]:
    return [finding.label for finding in run(text, **options)]


# ------------------------------------------------------- the unconfigured case first


def test_no_countries_reports_that_rather_than_a_clean_scan() -> None:
    found = run("Strada Lipscani 12, 010101 Bucuresti")
    assert [f.label for f in found] == ["countries_not_configured"]
    assert found[0].action == "log"


def test_the_unconfigured_finding_never_blocks() -> None:
    found = DETECTOR.run("x", DetectorConfig(on_fail="block"), CTX)
    assert found[0].action == "log"


def test_an_unknown_country_raises_rather_than_reporting_everything() -> None:
    # An unknown code matches nothing, so every postcode would be reported.
    with pytest.raises(PostalCodeDataError, match="no rule for country"):
        run("Strada Lipscani 12, 010101", countries=["xx"])


# ---------------------------------------------------- every country accepts its own


COUNTRIES = sorted(load_countries())


@pytest.mark.parametrize("code", COUNTRIES)
def test_each_country_accepts_its_own_example(code: str) -> None:
    """A pattern that rejects the country's own example is a typo, and there are 29.

    The example is in the data file for this test rather than for documentation.
    """
    country = load_countries()[code]
    import yaml

    from flowx_border.detectors.postal_code import _DATA

    raw = yaml.safe_load(_DATA.read_text(encoding="utf-8"))
    example = raw["countries"][code]["example"]
    assert country.accepts(example), f"{code} rejects its own example {example!r}"


def test_the_data_file_covers_the_countries_of_all_26_languages() -> None:
    # 29 countries for 26 languages, because a language is not a country: German is
    # official in four of them and each has its own postcode system.
    assert len(load_countries()) == 29


def test_the_unreviewed_countries_are_reported_rather_than_hidden() -> None:
    # None of these has been checked against a postal authority's own validator, and a
    # coverage table has to be able to say so.
    assert len(unreviewed_countries()) == 29


# ------------------------------------------------------------ the range rules bite


@pytest.mark.parametrize(
    ("text", "country"),
    [
        ("Calle Mayor 1, 99123 Madrid", "es"),  # province 99, and Spain has 01 to 52
        ("rue de Rivoli 1, 96000 Paris", "fr"),  # departement 96 is not allocated
        ("Sokak 5, 99010 Istanbul", "tr"),  # province 99, and Turkey has 01 to 81
    ],
)
def test_a_code_outside_a_published_range_is_malformed(text: str, country: str) -> None:
    """The part that goes beyond shape, and the reason the data file has ranges.

    Each of these is well formed and cannot exist, which is a different and more useful
    statement than "this is not five digits".
    """
    assert labels(text, countries=[country]) == ["postcode_malformed"], text


@pytest.mark.parametrize(
    ("text", "country"),
    [
        ("Calle Mayor 1, 28001 Madrid", "es"),
        ("rue de Rivoli 1, 75001 Paris", "fr"),
        ("Sokak 5, 34010 Istanbul", "tr"),
    ],
)
def test_a_code_inside_the_range_is_clean(text: str, country: str) -> None:
    assert run(text, countries=[country]) == [], text


def test_a_dutch_suffix_that_is_never_issued_is_malformed() -> None:
    # SA, SD and SS are not issued. A national rule rather than a shape one.
    assert labels("Herengracht 100, 1012 SS Amsterdam", countries=["nl"]) == [
        "postcode_malformed"
    ]
    assert run("Herengracht 100, 1012 AB Amsterdam", countries=["nl"]) == []


# ------------------------------------------------- the two findings mean two things


def test_a_code_for_another_country_is_not_called_malformed() -> None:
    """`01010` is a perfectly good five digit code. It is not a Romanian one.

    Telling somebody their postcode is malformed when it is a well-formed German one is
    a different and less useful statement than telling them it is for the wrong country.
    """
    assert labels("Strada Lipscani 12, 01010 Bucuresti", countries=["ro"]) == [
        "postcode_wrong_country"
    ]


def test_a_code_for_a_configured_country_is_clean_even_in_a_mixed_policy() -> None:
    assert run("Strada Lipscani 12, 010101 Bucuresti", countries=["ro", "de"]) == []
    assert run("Bahnhofstrasse 1, 10115 Berlin", countries=["ro", "de"]) == []


# ------------------------------------------------- ordinary numbers are not postcodes


def test_a_price_and_a_year_are_not_reported() -> None:
    """The failure that would get this detector switched off.

    An earlier version reported the year in "dated 2026", because the Spanish cue list
    contains `c` for calle and it was matched as a substring rather than as a word.
    """
    assert run("The invoice is 412 EUR and dated 2026.", countries=["de", "nl"]) == []
    assert run("Your balance is 4120 EUR this morning.", countries=["at"]) == []


def test_a_house_number_beside_a_postcode_is_not_reported() -> None:
    """The other half of the same problem.

    `100` is three digits and no country in the file issues a three digit code, so it
    is not a postcode that went wrong, it is not a postcode. An earlier version compared
    digit counts within one and reported every house number in the Netherlands.
    """
    assert run("Herengracht 100, 1012 AB Amsterdam", countries=["nl"]) == []


def test_nothing_is_reported_without_a_cue() -> None:
    # A bare number with no address word near it is not treated as a postcode at all.
    assert run("Reference 01010 applies.", countries=["ro"]) == []


def test_the_cue_requirement_can_be_relaxed_for_a_form_field() -> None:
    assert labels("01010", countries=["ro"], require_cue=False) == [
        "postcode_wrong_country"
    ]


def test_an_empty_output_is_not_an_error() -> None:
    assert run("", countries=["ro"]) == []


# --------------------------------------------------------------- cues in 26 languages

#: language -> (country, a valid address, the same address with a broken postcode).
#:
#: The broken variant is explicit rather than derived. An earlier version made one by
#: replacing digits, which does not break anything for a country whose rule is shape
#: only: Romania accepts any six digits, so `999999` is as valid as `010101` and the
#: test passed while checking nothing. Each break below changes the shape or violates a
#: published range.
ADDRESSES: dict[str, tuple[str, str, str]] = {
    "en": ("ie", "12 Dame Street, D02 AF30 Dublin", "12 Dame Street, 10115 Dublin"),
    "ro": (
        "ro",
        "Strada Lipscani 12, 010101 Bucuresti",
        "Strada Lipscani 12, 01010 Bucuresti",
    ),
    "bg": ("bg", "улица Витоша 5, 1000 София", "улица Витоша 5, 10115 София"),
    "cs": ("cz", "Národní ulice 7, 110 00 Praha", "Národní ulice 7, 91500 Praha"),
    "da": ("dk", "Nørregade 5, 1050 København", "Nørregade 5, 10115 København"),
    "de": ("de", "Bahnhofstrasse 1, 10115 Berlin", "Bahnhofstrasse 1, 1011 Berlin"),
    "el": ("gr", "οδός Ερμού 10, 104 31 Αθήνα", "οδός Ερμού 10, 1043 Αθήνα"),
    "es": ("es", "Calle Mayor 1, 28001 Madrid", "Calle Mayor 1, 99123 Madrid"),
    "et": ("ee", "Pikk tänav 3, 10111 Tallinn", "Pikk tänav 3, 1011 Tallinn"),
    "fi": (
        "fi",
        "Mannerheimintie 5, 00100 Helsinki",
        "Mannerheimintie 5, 0010 Helsinki",
    ),
    "fr": ("fr", "rue de Rivoli 1, 75001 Paris", "rue de Rivoli 1, 96000 Paris"),
    "ga": (
        "ie",
        "Sráid Grafton 10, D02 AF30 Baile Átha Cliath",
        "Sráid Grafton 10, 10115 Baile Átha Cliath",
    ),
    "hr": ("hr", "Ilica ulica 5, 10000 Zagreb", "Ilica ulica 5, 1000 Zagreb"),
    "hu": ("hu", "Kossuth utca 3, 1051 Budapest", "Kossuth utca 3, 10515 Budapest"),
    "it": ("it", "via del Corso 1, 00184 Roma", "via del Corso 1, 0018 Roma"),
    "lt": (
        "lt",
        "Gedimino prospektas 9, 01100 Vilnius",
        "Gedimino prospektas 9, 0110 Vilnius",
    ),
    "lv": ("lv", "Brīvības iela 5, LV-1050 Rīga", "Brīvības iela 5, 10500 Rīga"),
    "mt": (
        "mt",
        "Triq ir-Repubblika 10, VLT 1117 Valletta",
        "Triq ir-Repubblika 10, 11175 Valletta",
    ),
    "nl": (
        "nl",
        "Herengracht 100, 1012 AB Amsterdam",
        "Herengracht 100, 1012 SS Amsterdam",
    ),
    "pl": (
        "pl",
        "ulica Marszalkowska 1, 00-950 Warszawa",
        "ulica Marszalkowska 1, 00950 Warszawa",
    ),
    "pt": ("pt", "Rua Augusta 10, 1000-100 Lisboa", "Rua Augusta 10, 10001 Lisboa"),
    "sk": (
        "sk",
        "Hlavná ulica 5, 811 01 Bratislava",
        "Hlavná ulica 5, 8110 Bratislava",
    ),
    "sl": (
        "si",
        "Slovenska cesta 5, 1000 Ljubljana",
        "Slovenska cesta 5, 10005 Ljubljana",
    ),
    "sv": ("se", "Storgatan 5, 111 29 Stockholm", "Storgatan 5, 1112 Stockholm"),
    "tr": (
        "tr",
        "Istiklal Caddesi 5, 34010 Istanbul",
        "Istiklal Caddesi 5, 99010 Istanbul",
    ),
    "az": ("az", "Nizami küçəsi 10, AZ 1000 Baku", "Nizami küçəsi 10, 10005 Baku"),
}

CLAIMED = {
    "az",
    "bg",
    "cs",
    "da",
    "de",
    "el",
    "en",
    "es",
    "et",
    "fi",
    "fr",
    "ga",
    "hr",
    "hu",
    "it",
    "lt",
    "lv",
    "mt",
    "nl",
    "pl",
    "pt",
    "ro",
    "sk",
    "sl",
    "sv",
    "tr",
}


def test_the_fixtures_cover_every_language_the_project_claims() -> None:
    assert set(ADDRESSES) == CLAIMED


@pytest.mark.parametrize("language", sorted(ADDRESSES))
def test_a_valid_address_in_each_language_is_clean(language: str) -> None:
    country, text, _ = ADDRESSES[language]
    assert run(text, countries=[country]) == [], f"{language}: {text}"


@pytest.mark.parametrize("language", sorted(ADDRESSES))
def test_a_broken_postcode_in_each_language_is_caught(language: str) -> None:
    """The test that gives the one above its meaning.

    A clean result can mean the address is valid, or it can mean the cue for that
    language is missing and nothing was looked at. Breaking the postcode separates the
    two: if this passes, the cue works. It is how the missing Turkish possessive was
    found, since a street there is `Caddesi` rather than `cadde`.
    """
    country, _, broken = ADDRESSES[language]
    assert labels(broken, countries=[country]), (
        f"{language}: nothing checked in {broken!r}, so the cue is missing"
    )


# ------------------------------------------------------------ compound street names


@pytest.mark.parametrize(
    ("text", "country"),
    [
        ("Herengracht 100, 1012 SS Amsterdam", "nl"),
        ("Bahnhofstrasse 1, 1011 Berlin", "de"),
        ("Storgatan 5, 1112 Stockholm", "se"),
        ("Nørregade 5, 10500 København", "dk"),
        ("Mannerheimintie 5, 0010 Helsinki", "fi"),
        ("Pikk tänav 3, 1011 Tallinn", "ee"),
        ("Gedimino gatvė 9, 0110 Vilnius", "lt"),
        ("Brīvības iela 5, 10500 Rīga", "lv"),
    ],
)
def test_a_compound_street_name_is_still_a_cue(text: str, country: str) -> None:
    """`Herengracht` is one word, so a whole-word cue matches nothing in it.

    Without suffix matching the detector checks nothing in these languages, which is a
    silent gap rather than a visible one, and they are exactly the languages where a
    street name is written as a single token.
    """
    assert labels(text, countries=[country]), text


def test_a_suffix_cue_has_to_end_the_word() -> None:
    # `gracht` matches `Herengracht` and must not match `grachten`.
    assert "gracht" in load_suffix_cues()
    assert run("grachtenpand 1011 XX", countries=["nl"]) == []


def test_a_code_too_short_to_be_any_countrys_is_not_reported() -> None:
    """A stated limit rather than a bug, and the price of not reporting house numbers.

    `105` beside a Danish street is visibly a broken postcode to a reader, and this
    detector says nothing about it, because no country in the file issues a three digit
    code and the alternative is reporting every house number in Europe. The detector
    reports codes that are malformed for a configured country and codes that belong to
    another one. A token that is nobody's postcode is not one of those.
    """
    assert run("Nørregade 5, 105 København", countries=["dk"]) == []


def test_the_candidate_does_not_swallow_the_town() -> None:
    """`10005 Baku` was one candidate until the pattern learned to stop.

    No country issues a code ending in a four letter word, so the whole thing matched
    nothing and the broken code went unreported.
    """
    found = run("Nizami küçəsi 10, 10005 Baku", countries=["az"])
    assert found
    assert found[0].span is not None
    assert "Nizami küçəsi 10, 10005 Baku"[slice(*found[0].span)] == "10005"


# --------------------------------------------------------------------------- plumbing


def test_the_cue_lists_are_not_empty() -> None:
    assert len(load_cues()) > 100
    assert len(load_suffix_cues()) > 20


def test_the_detector_matches_the_catalogue() -> None:
    from flowx_border.detectors.catalogue import CATALOGUE, CORE

    spec = CATALOGUE["postal_code"]
    assert (DETECTOR.id, DETECTOR.tier) == ("postal_code", spec.tier)
    assert DETECTOR.sides == spec.sides
    # In CORE: the data ships with the package, so it needs no network and no extra.
    assert "postal_code" in CORE


def test_warm_is_idempotent() -> None:
    DETECTOR.warm()
    DETECTOR.warm()
    assert run("Calle Mayor 1, 28001 Madrid", countries=["es"]) == []


def test_findings_never_carry_the_text() -> None:
    for finding in run("Calle Mayor 1, 99123 Madrid", countries=["es"]):
        assert "99123" not in finding.model_dump_json()
        assert "Madrid" not in finding.model_dump_json()
