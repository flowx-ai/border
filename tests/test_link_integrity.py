# SPDX-License-Identifier: Apache-2.0
"""Tests for the link_integrity detector.

Four questions about each link, all answerable without the network: does the visible
text name a different site from the one the link goes to, does the target hide its
real host behind userinfo, is the target host a confusable spelling, and is it a bare
IP address.

The 26-language sweep has two halves, as in test_markup_injection.py. The clean half
is ordinary prose carrying ordinary links, several of them to internationalised hosts
in the language's own script, because a detector that fires on `münchen.example` or on
a Bulgarian `.бг` address is broken for the languages this library claims. The payload
half puts the same deceptive link inside each language's prose.
"""

from __future__ import annotations

import pytest

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.link_integrity import (
    LinkIntegrityDetector,
    registrable_domain,
)
from flowx_border.detectors.multilingual import LANGUAGES as CLAIMED
from flowx_border.types import Finding

DETECTOR = LinkIntegrityDetector()
CFG = DetectorConfig(on_fail="flag")
CTX = Context()


def run(text: str, cfg: DetectorConfig = CFG) -> list[Finding]:
    return DETECTOR.run(text, cfg, CTX)


def labels(text: str, cfg: DetectorConfig = CFG) -> list[str]:
    return [finding.label for finding in run(text, cfg)]


# ------------------------------------------------------------- text names another site


@pytest.mark.parametrize(
    "text",
    [
        "[bank.example.com](https://evil.test/login)",
        "[https://bank.example.com/login](https://evil.test/login)",
        "[www.bank.com](http://bank.com.evil.test/)",
        '<a href="https://evil.test/login">bank.example.com</a>',
        '<a href="https://evil.test/login"><b>https://bank.com</b></a>',
        "[paypal.com][1]\n\n[1]: https://paypa1.test/",
        "[example.co.uk](https://evil.co.uk/)",
        "[**bank.com**](https://evil.test/)",
    ],
)
def test_visible_host_differs_from_the_target(text: str) -> None:
    assert labels(text) == ["link_text_mismatch"], text


@pytest.mark.parametrize(
    "text",
    [
        # Same registrable domain, different subdomain or path.
        "[docs.python.org](https://python.org/docs)",
        "[python.org](https://docs.python.org/3/)",
        "[https://bank.com](https://www.bank.com/login)",
        "[example.co.uk](https://shop.example.co.uk/)",
        # One host, two spellings.
        "[münchen.example](https://xn--mnchen-3ya.example/)",
        # Anchor text that names no host at all, which is the ordinary case.
        "[your statement](https://bank.com/statements)",
        "[Node.js](https://nodejs.org/)",
        "[version 1.2](https://example.com/releases)",
        # A filename, not a host, although .rs and .md are ccTLDs.
        "[main.rs](https://github.com/org/repo/blob/main/src/main.rs)",
        "[README.md](https://github.com/org/repo)",
        # A relative or non-web target has no host to compare.
        "[bank.com](/login)",
        "[support@bank.com](mailto:support@bank.com)",
        # A version number is not an address. Every changelog links them.
        "[3.4.9](https://github.com/org/repo/compare/3.4.8...3.4.9)",
        # Loopback is the reader's own machine, and every quickstart links to it.
        "[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)",
        "Open http://127.0.0.1:8000 or http://[::1]:8000/ in a browser.",
        # An image is not a link a reader follows.
        "![bank.com](https://cdn.example.net/logo.png)",
    ],
)
def test_matching_or_hostless_links_are_clean(text: str) -> None:
    assert run(text) == [], text


def test_the_span_covers_the_whole_link_so_redaction_removes_it() -> None:
    text = "Log in here: [bank.com](https://evil.test/) and nowhere else."
    (finding,) = run(text)
    assert finding.span is not None
    assert text[slice(*finding.span)] == "[bank.com](https://evil.test/)"


def test_an_html_link_span_covers_the_element() -> None:
    text = 'See <a href="https://evil.test/">bank.com</a> now.'
    (finding,) = run(text)
    assert finding.span is not None
    assert text[slice(*finding.span)] == '<a href="https://evil.test/">bank.com</a>'


def test_entity_encoded_href_is_decoded_first() -> None:
    # `&#64;` is `@`, so this href is userinfo pointing at evil.test.
    assert labels('<a href="https://bank.com&#64;evil.test/">x</a>') == [
        "link_userinfo"
    ]


# --------------------------------------------------------------- the target on its own


@pytest.mark.parametrize(
    "text",
    [
        "[Log in](https://bank.com@evil.test/login)",
        "https://bank.com@evil.test/login",
        "[bank.com](https://bank.com@evil.test/)",
        "[x](https://user:pw@example.com/)",
    ],
)
def test_userinfo_in_the_target_is_reported(text: str) -> None:
    assert labels(text) == ["link_userinfo"], text


@pytest.mark.parametrize(
    "text",
    [
        "[Log in](http://192.168.10.5/login)",
        "[Log in](http://[2001:db8::1]/login)",
        "http://203.0.113.9/reset",
        # Loopback in an unusual spelling is not exempt: nobody writes it that way.
        "[Log in](http://127.1/)",
        # Integer and hex spellings that browsers still resolve.
        "[Log in](http://3232235777/)",
        "[Log in](http://0x7f.0.0.1/)",
    ],
)
def test_ip_literal_targets_are_reported(text: str) -> None:
    assert labels(text) == ["link_ip_host"], text


@pytest.mark.parametrize(
    "text",
    [
        # Cyrillic а in a Latin label.
        "[Log in](https://pаypal.com/)",
        # The same, written as punycode.
        "[Log in](https://xn--pypal-4ve.com/)",
        # An all-Cyrillic label made only of Latin lookalikes, under .com.
        "[Log in](https://аррӏе.com/)",
        # Greek omicron in a Latin label.
        "https://gοogle.com/",
        # Undecodable punycode is not a host anyone can read.
        "[Log in](https://xn--zz.com/)",
    ],
)
def test_confusable_hosts_are_reported(text: str) -> None:
    assert labels(text) == ["link_confusable_host"], text


def test_a_single_script_idn_host_is_clean_by_default() -> None:
    assert run("[Stadt](https://münchen.example/)") == []
    assert run("[сайт](https://пример.бг/)") == []


def test_idn_hosts_all_reports_every_internationalised_host() -> None:
    cfg = DetectorConfig(on_fail="flag", options={"idn_hosts": "all"})
    assert labels("[Stadt](https://münchen.example/)", cfg) == ["link_idn_host"]
    assert labels("[Stadt](https://xn--mnchen-3ya.example/)", cfg) == ["link_idn_host"]
    # A confusable one still carries the more specific label.
    assert labels("[x](https://pаypal.com/)", cfg) == ["link_confusable_host"]


def test_an_unknown_idn_hosts_value_is_refused_rather_than_ignored() -> None:
    cfg = DetectorConfig(on_fail="flag", options={"idn_hosts": "sometimes"})
    with pytest.raises(ValueError, match="idn_hosts"):
        run("[x](https://example.com/)", cfg)


def test_one_link_is_one_finding_even_when_several_rules_apply() -> None:
    # Userinfo and a text mismatch at once. One link, one row, and the row names the
    # trick rather than only the symptom.
    found = run("[bank.com](https://bank.com@192.168.0.1/)")
    assert [f.label for f in found] == ["link_userinfo"]


def test_a_bare_url_inside_a_markdown_link_is_not_counted_twice() -> None:
    assert len(run("[Log in](https://bank.com@evil.test/)")) == 1


def test_an_ordinary_bare_url_is_clean() -> None:
    assert run("Docs are at https://docs.python.org/3/library/re.html.") == []


# ------------------------------------------------------------- registrable domain rule


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("www.bank.com", "bank.com"),
        ("bank.com.", "bank.com"),
        ("shop.example.co.uk", "example.co.uk"),
        ("a.b.example.com.au", "example.com.au"),
        ("example.com.ro", "example.com.ro"),
        ("münchen.example", "xn--mnchen-3ya.example"),
        ("localhost", "localhost"),
        ("192.168.0.1", "192.168.0.1"),
    ],
)
def test_registrable_domain(host: str, expected: str) -> None:
    assert registrable_domain(host) == expected


# ------------------------------------------------------------------ 26 languages


CLEAN: dict[str, str] = {
    "en": "Your statement is ready: [download it](https://bank.example/statements) "
    "or visit [bank.example](https://www.bank.example/).",
    "ro": "Extrasul este disponibil: [descărcați-l](https://banca.example.ro/extrase) "
    "sau vizitați [banca.example.ro](https://www.banca.example.ro/).",
    "bg": "Извлечението е готово: [изтеглете го](https://пример.бг/извлечения) "
    "или посетете [пример.бг](https://www.пример.бг/).",
    "cs": "Výpis je připraven: [stáhněte si ho](https://banka.example.cz/vypisy) "
    "nebo navštivte [banka.example.cz](https://www.banka.example.cz/).",
    "da": "Dit kontoudtog er klar: [hent det](https://banken.example.dk/udtog) "
    "eller besøg [banken.example.dk](https://www.banken.example.dk/).",
    "de": "Ihr Kontoauszug ist bereit: [herunterladen](https://münchen.example/auszug) "
    "oder besuchen Sie [münchen.example](https://www.xn--mnchen-3ya.example/).",
    "el": "Η κίνηση λογαριασμού είναι έτοιμη: [λήψη](https://τράπεζα.ελ/κινήσεις) "
    "ή επισκεφθείτε [τράπεζα.ελ](https://www.τράπεζα.ελ/).",
    "es": "Su extracto está listo: [descárguelo](https://banco.example.es/extractos) "
    "o visite [banco.example.es](https://www.banco.example.es/).",
    "et": "Konto väljavõte on valmis: [laadige](https://pank.example.ee/valjavote) "
    "või külastage [pank.example.ee](https://www.pank.example.ee/).",
    "fi": "Tiliote on valmis: [lataa se](https://pankki.example.fi/tiliotteet) "
    "tai käy osoitteessa [pankki.example.fi](https://www.pankki.example.fi/).",
    "fr": "Votre relevé est prêt : [téléchargez-le](https://banque.example.fr/releves) "
    "ou consultez [banque.example.fr](https://www.banque.example.fr/).",
    "ga": "Tá do ráiteas réidh: [íoslódáil é](https://banc.example.ie/raitis) "
    "nó tabhair cuairt ar [banc.example.ie](https://www.banc.example.ie/).",
    "hr": "Izvod je spreman: [preuzmite ga](https://banka.example.hr/izvodi) "
    "ili posjetite [banka.example.hr](https://www.banka.example.hr/).",
    "hu": "A kivonat elkészült: [töltse le](https://bank.example.hu/kivonatok) "
    "vagy látogasson el ide: [bank.example.hu](https://www.bank.example.hu/).",
    "it": "L'estratto conto è pronto: [scaricalo](https://banca.example.it/estratti) "
    "oppure visita [banca.example.it](https://www.banca.example.it/).",
    "lt": "Išrašas paruoštas: [atsisiųskite](https://bankas.example.lt/israsai) "
    "arba apsilankykite [bankas.example.lt](https://www.bankas.example.lt/).",
    "lv": "Izraksts ir gatavs: [lejupielādējiet](https://banka.example.lv/izraksti) "
    "vai apmeklējiet [banka.example.lv](https://www.banka.example.lv/).",
    "mt": "Ir-rendikont huwa lest: [niżżlu](https://bank.example.com.mt/rendikonti) "
    "jew żur [bank.example.com.mt](https://www.bank.example.com.mt/).",
    "nl": "Uw afschrift staat klaar: [download het](https://bank.example.nl/afschrift) "
    "of bezoek [bank.example.nl](https://www.bank.example.nl/).",
    "pl": "Wyciąg jest gotowy: [pobierz go](https://łódź.example.pl/wyciagi) "
    "lub odwiedź [łódź.example.pl](https://www.łódź.example.pl/).",
    "pt": "O seu extrato está pronto: [descarregue](https://banco.example.pt/extrato) "
    "ou visite [banco.example.pt](https://www.banco.example.pt/).",
    "sk": "Výpis je pripravený: [stiahnite si ho](https://banka.example.sk/vypisy) "
    "alebo navštívte [banka.example.sk](https://www.banka.example.sk/).",
    "sl": "Izpisek je pripravljen: [prenesite ga](https://banka.example.si/izpiski) "
    "ali obiščite [banka.example.si](https://www.banka.example.si/).",
    "sv": "Ditt kontoutdrag är klart: [ladda ner](https://banken.example.se/utdrag) "
    "eller besök [banken.example.se](https://www.banken.example.se/).",
    "tr": "Hesap özetiniz hazır: [indirin](https://işbank.example.com.tr/ozet) "
    "veya [işbank.example.com.tr](https://www.işbank.example.com.tr/) adresine gidin.",
    "az": "Hesabdan çıxarış hazırdır: [yükləyin](https://bank.example.az/cixaris) "
    "və ya [bank.example.az](https://www.bank.example.az/) ünvanına daxil olun.",
}

#: The deceptive link, phrased in each language as the visible text a reader trusts.
DECEPTIVE: dict[str, str] = {
    code: text.replace("https://www.", "https://evil.test/www.", 1)
    for code, text in CLEAN.items()
}


def test_the_fixtures_cover_every_language_the_project_claims() -> None:
    assert set(CLEAN) == CLAIMED
    assert set(DECEPTIVE) == CLAIMED


@pytest.mark.parametrize("code", sorted(CLEAN))
def test_ordinary_links_in_each_language_are_clean(code: str) -> None:
    assert run(CLEAN[code]) == [], f"{code}: {CLEAN[code]}"


@pytest.mark.parametrize("code", sorted(DECEPTIVE))
def test_a_mismatched_link_in_each_language_is_found(code: str) -> None:
    assert labels(DECEPTIVE[code]) == ["link_text_mismatch"], code


@pytest.mark.parametrize("code", sorted(CLEAN))
def test_a_userinfo_link_inside_prose_in_each_language_is_found(code: str) -> None:
    text = f"{CLEAN[code]} https://bank.example@evil.test/"
    assert labels(text) == ["link_userinfo"], code


# --------------------------------------------------------------------------- plumbing


def test_the_detector_matches_the_catalogue() -> None:
    from flowx_border.detectors.catalogue import CATALOGUE

    spec = CATALOGUE["link_integrity"]
    assert (DETECTOR.id, DETECTOR.tier) == ("link_integrity", spec.tier)
    assert DETECTOR.sides == spec.sides
    assert spec.requires == frozenset()


def test_the_registry_builds_it() -> None:
    from flowx_border.detectors.catalogue import CORE
    from flowx_border.registry import loaded_detectors

    assert "link_integrity" in CORE
    assert isinstance(loaded_detectors()["link_integrity"], LinkIntegrityDetector)


def test_warm_is_idempotent() -> None:
    DETECTOR.warm()
    DETECTOR.warm()
    assert labels("[bank.com](https://evil.test/)") == ["link_text_mismatch"]


def test_an_empty_text_is_not_an_error() -> None:
    assert run("") == []


def test_findings_never_carry_the_text() -> None:
    for finding in run("[bank412.com](https://evil412.test/)"):
        assert "412" not in finding.model_dump_json()


def test_the_action_comes_from_the_policy() -> None:
    cfg = DetectorConfig(on_fail="redact")
    (finding,) = run("[bank.com](https://evil.test/)", cfg)
    assert finding.action == "redact"
