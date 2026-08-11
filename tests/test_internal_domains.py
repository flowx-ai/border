# SPDX-License-Identifier: Apache-2.0
"""Tests for the internal_domains detector.

Three of these tests exist because the upstream validator gets them wrong, and two of
those three turn a leak detector into something that reports the wrong host: without a
left boundary it flags `notcorp.internal`, and without a right boundary it flags
`corp.internal.evil.net`, which is an attacker-controlled name that merely starts with
yours. Reporting that as your internal domain is precisely backwards.

The 26-language sweep covers the gap rather than the bugs. A domain is one host whether
it is written in Unicode or in punycode, the two spellings share no characters, and a
model writing an answer has no reason to pick the one the policy happened to use.
"""

from __future__ import annotations

import pytest

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.internal_domains import (
    InternalDomainsDetector,
    idn_variants,
)
from flowx_border.types import Finding

DETECTOR = InternalDomainsDetector()
CTX = Context()


def run(text: str, *domains: str) -> list[Finding]:
    return DETECTOR.run(
        text, DetectorConfig(on_fail="flag", options={"domains": list(domains)}), CTX
    )


def labels(text: str, *domains: str) -> list[str]:
    return [finding.label for finding in run(text, *domains)]


# ------------------------------------------------------- the unconfigured case first


def test_no_domains_reports_that_rather_than_a_clean_scan() -> None:
    found = DETECTOR.run("Anything at all.", DetectorConfig(on_fail="flag"), CTX)
    assert [f.label for f in found] == ["domains_not_configured"]
    assert found[0].action == "log"


def test_the_unconfigured_finding_never_blocks() -> None:
    found = DETECTOR.run("text", DetectorConfig(on_fail="block"), CTX)
    assert found[0].action == "log"


# ------------------------------------------------------------------- basic matching


def test_a_listed_domain_is_found() -> None:
    assert labels("See corp.internal for details.", "corp.internal") == [
        "internal_domain"
    ]


def test_a_subdomain_of_a_listed_domain_is_found() -> None:
    # What anyone configuring this expects: listing the apex covers what is under it.
    assert labels("See wiki.corp.internal for details.", "corp.internal") == [
        "internal_domain"
    ]


def test_a_domain_inside_a_url_is_found() -> None:
    found = run("Read https://wiki.corp.internal/guide today.", "corp.internal")
    assert len(found) == 1


def test_an_unlisted_domain_is_not_found() -> None:
    assert run("See example.com for details.", "corp.internal") == []


def test_the_span_points_at_the_host() -> None:
    text = "Read https://wiki.corp.internal/guide today."
    finding = run(text, "corp.internal")[0]
    assert finding.span is not None
    assert text[slice(*finding.span)] == "wiki.corp.internal"


def test_matching_ignores_case() -> None:
    assert labels("See CORP.INTERNAL for details.", "corp.internal") == [
        "internal_domain"
    ]
    assert labels("See corp.internal today.", "Corp.Internal") == ["internal_domain"]


# ------------------------------------------------------- the upstream boundary bugs


def test_a_longer_host_ending_in_the_domain_is_not_reported() -> None:
    """Without a left boundary, banning `corp.internal` flags `notcorp.internal`.

    That is somebody else's host, and usually a real one.
    """
    assert run("See notcorp.internal for details.", "corp.internal") == []


def test_a_host_that_merely_starts_with_the_domain_is_not_reported() -> None:
    """Without a right boundary, `corp.internal` matches inside
    `corp.internal.evil.example`.

    That is the shape of a phishing name: an attacker-controlled host prefixed with
    yours. Reporting it as your internal domain points the reader at the wrong problem.
    """
    assert run("Do not visit corp.internal.evil.example.", "corp.internal") == []


def test_a_domain_at_the_end_of_a_sentence_is_still_reported() -> None:
    # The right boundary must reject another label, not an ordinary full stop.
    assert labels("The host is corp.internal.", "corp.internal") == ["internal_domain"]


def test_a_dot_does_not_have_to_be_a_wildcard() -> None:
    # re.escape on the domain, so the dots are literal.
    assert run("See corpxinternal for details.", "corp.internal") == []


# ------------------------------------------------------------ internationalised names


def test_a_unicode_domain_matches_its_punycode_spelling() -> None:
    assert labels("Visit xn--mnchen-3ya.example today.", "münchen.example") == [
        "internal_domain"
    ]


def test_a_punycode_domain_matches_its_unicode_spelling() -> None:
    assert labels("Visit münchen.example today.", "xn--mnchen-3ya.example") == [
        "internal_domain"
    ]


def test_both_spellings_are_generated_from_either() -> None:
    variants = idn_variants("münchen.example")
    assert "münchen.example" in variants
    assert "xn--mnchen-3ya.example" in variants


def test_a_domain_the_idna_codec_rejects_is_used_as_written() -> None:
    # An underscore is common in an internal hostname and the codec refuses it. Dropping
    # such a domain from the list would be a silent gap in a security check.
    assert idn_variants("my_host.internal") == ("my_host.internal",)
    assert labels("See my_host.internal today.", "my_host.internal") == [
        "internal_domain"
    ]


# --------------------------------------------------------------------- all 26 languages

#: code -> (internal domain as the policy writes it, a sentence in that language
#: containing it, an ordinary sentence that does not).
LANGUAGES: dict[str, tuple[str, str, str]] = {
    "en": (
        "corp.internal",
        "The guide is on wiki.corp.internal today.",
        "The guide is on the shared drive.",
    ),
    "ro": (
        "intern.exemplu.ro",
        "Ghidul este pe wiki.intern.exemplu.ro astăzi.",
        "Ghidul este pe unitatea partajată.",
    ),
    "bg": (
        "вътрешен.пример.bg",
        "Ръководството е на вътрешен.пример.bg днес.",
        "Ръководството е на споделеното устройство.",
    ),
    "cs": (
        "interni.priklad.cz",
        "Průvodce je dnes na wiki.interni.priklad.cz.",
        "Průvodce je na sdíleném disku.",
    ),
    "da": (
        "intern.eksempel.dk",
        "Vejledningen er på wiki.intern.eksempel.dk i dag.",
        "Vejledningen er på det delte drev.",
    ),
    "de": (
        "intern.beispiel.de",
        "Die Anleitung liegt heute auf wiki.intern.beispiel.de.",
        "Die Anleitung liegt auf dem gemeinsamen Laufwerk.",
    ),
    "el": (
        "εσωτερικό.παράδειγμα.gr",
        "Ο οδηγός είναι στο εσωτερικό.παράδειγμα.gr σήμερα.",
        "Ο οδηγός είναι στον κοινόχρηστο δίσκο.",
    ),
    "es": (
        "interno.ejemplo.es",
        "La guía está hoy en wiki.interno.ejemplo.es.",
        "La guía está en la unidad compartida.",
    ),
    "et": (
        "sisemine.naide.ee",
        "Juhend on täna aadressil wiki.sisemine.naide.ee.",
        "Juhend on jagatud kettal.",
    ),
    "fi": (
        "sisainen.esimerkki.fi",
        "Opas on tänään osoitteessa wiki.sisainen.esimerkki.fi.",
        "Opas on jaetulla asemalla.",
    ),
    "fr": (
        "interne.exemple.fr",
        "Le guide est aujourd'hui sur wiki.interne.exemple.fr.",
        "Le guide est sur le lecteur partagé.",
    ),
    "ga": (
        "inmheanach.sampla.ie",
        "Tá an treoir ar wiki.inmheanach.sampla.ie inniu.",
        "Tá an treoir ar an tiomántán roinnte.",
    ),
    "hr": (
        "interni.primjer.hr",
        "Vodič je danas na wiki.interni.primjer.hr.",
        "Vodič je na dijeljenom disku.",
    ),
    "hu": (
        "belso.pelda.hu",
        "Az útmutató ma a wiki.belso.pelda.hu címen van.",
        "Az útmutató a megosztott meghajtón van.",
    ),
    "it": (
        "interno.esempio.it",
        "La guida è oggi su wiki.interno.esempio.it.",
        "La guida è sull'unità condivisa.",
    ),
    "lt": (
        "vidinis.pavyzdys.lt",
        "Vadovas šiandien yra wiki.vidinis.pavyzdys.lt.",
        "Vadovas yra bendrame diske.",
    ),
    "lv": (
        "ieksejais.piemers.lv",
        "Rokasgrāmata šodien ir wiki.ieksejais.piemers.lv.",
        "Rokasgrāmata ir koplietošanas diskā.",
    ),
    "mt": (
        "intern.ezempju.mt",
        "Il-gwida llum tinsab fuq wiki.intern.ezempju.mt.",
        "Il-gwida tinsab fuq id-drajv kondiviż.",
    ),
    "nl": (
        "intern.voorbeeld.nl",
        "De handleiding staat vandaag op wiki.intern.voorbeeld.nl.",
        "De handleiding staat op de gedeelde schijf.",
    ),
    "pl": (
        "wewnetrzny.przyklad.pl",
        "Przewodnik jest dziś na wiki.wewnetrzny.przyklad.pl.",
        "Przewodnik jest na dysku współdzielonym.",
    ),
    "pt": (
        "interno.exemplo.pt",
        "O guia está hoje em wiki.interno.exemplo.pt.",
        "O guia está na unidade partilhada.",
    ),
    "sk": (
        "interny.priklad.sk",
        "Sprievodca je dnes na wiki.interny.priklad.sk.",
        "Sprievodca je na zdieľanom disku.",
    ),
    "sl": (
        "interni.primer.si",
        "Vodnik je danes na wiki.interni.primer.si.",
        "Vodnik je na skupnem disku.",
    ),
    "sv": (
        "intern.exempel.se",
        "Guiden finns i dag på wiki.intern.exempel.se.",
        "Guiden finns på den delade enheten.",
    ),
    "tr": (
        "dahili.ornek.com.tr",
        "Kılavuz bugün wiki.dahili.ornek.com.tr adresinde.",
        "Kılavuz paylaşılan sürücüde.",
    ),
    "az": (
        "daxili.numune.az",
        "Bələdçi bu gün wiki.daxili.numune.az ünvanındadır.",
        "Bələdçi paylaşılan diskdədir.",
    ),
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
    assert set(LANGUAGES) == CLAIMED


@pytest.mark.parametrize("code", sorted(LANGUAGES))
def test_a_domain_in_each_language_is_found(code: str) -> None:
    domain, positive, _ = LANGUAGES[code]
    assert labels(positive, domain) == ["internal_domain"], code


@pytest.mark.parametrize("code", sorted(LANGUAGES))
def test_an_ordinary_sentence_in_each_language_is_clean(code: str) -> None:
    domain, _, negative = LANGUAGES[code]
    assert run(negative, domain) == [], code


@pytest.mark.parametrize("code", sorted(LANGUAGES))
def test_the_span_is_exact_in_each_language(code: str) -> None:
    domain, positive, _ = LANGUAGES[code]
    finding = run(positive, domain)[0]
    assert finding.span is not None
    assert positive[slice(*finding.span)].casefold().endswith(domain.casefold()), code


# --------------------------------------------------------------------------- plumbing


def test_the_detector_matches_the_catalogue() -> None:
    from flowx_border.detectors.catalogue import CATALOGUE

    spec = CATALOGUE["internal_domains"]
    assert (DETECTOR.id, DETECTOR.tier) == ("internal_domains", spec.tier)
    assert DETECTOR.sides == spec.sides


def test_warm_is_idempotent() -> None:
    DETECTOR.warm()
    DETECTOR.warm()
    assert labels("See corp.internal today.", "corp.internal") == ["internal_domain"]


def test_findings_never_carry_the_text() -> None:
    for finding in run("Balance 412 EUR at corp.internal.", "corp.internal"):
        assert "412" not in finding.model_dump_json()
        assert "corp" not in finding.model_dump_json()
