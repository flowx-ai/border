# SPDX-License-Identifier: Apache-2.0
"""Tests for the markup_injection detector.

The 26-language sweep here is a false-positive sweep, which is unusual and is the whole
point. The validator this replaces reports an attack whenever `bleach.clean` changes the
string, so it fires on any text containing `<`, `>` or `&` for any reason. Every clean
fixture below therefore contains all three, in a sentence a real product would produce,
in each of the 26 languages. If a future change to the patterns starts matching ordinary
prose, these fail before anyone deploys it.

The payload fixtures then check the other half: that folding closes the evasions, so
case, zero-width characters, HTML entities and full-width Latin all arrive at the same
finding.
"""

from __future__ import annotations

import pytest

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.markup_injection import MarkupInjectionDetector
from flowx_border.detectors.multilingual import LANGUAGES as CLAIMED
from flowx_border.types import Finding

DETECTOR = MarkupInjectionDetector()
CFG = DetectorConfig(on_fail="flag")
CTX = Context()


def run(text: str) -> list[Finding]:
    return DETECTOR.run(text, CFG, CTX)


def labels(text: str) -> list[str]:
    return [finding.label for finding in run(text)]


# ------------------------------------------------------------------ the vectors

PAYLOADS = {
    "script_element": "<script>alert(1)</script>",
    "event_handler": '<img src=x onerror="alert(1)">',
    "javascript_url": '<a href="javascript:alert(1)">click</a>',
    "vbscript_url": '<a href="vbscript:msgbox(1)">click</a>',
    "data_url_html": '<a href="data:text/html;base64,PHNjcmlwdD4=">click</a>',
    "iframe_element": '<iframe src="//evil.example"></iframe>',
    "object_element": '<object data="//evil.example"></object>',
    "srcdoc_attribute": '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
    "meta_refresh": '<meta http-equiv="refresh" content="0;url=//evil.example">',
}


@pytest.mark.parametrize("label", sorted(PAYLOADS))
def test_each_named_vector_is_found(label: str) -> None:
    assert label in labels(PAYLOADS[label]), label


def test_a_span_points_at_the_payload_rather_than_the_whole_text() -> None:
    text = "Here you go: <script>alert(1)</script> and that is all."
    finding = next(f for f in run(text) if f.label == "script_element")
    assert finding.span is not None
    assert text[slice(*finding.span)].startswith("<script")


def test_one_payload_is_one_finding_even_when_two_rules_could_claim_it() -> None:
    # `<iframe srcdoc="...">` matches both the iframe rule and the srcdoc rule over
    # overlapping text. One payload should be one row in the record.
    found = run('<iframe srcdoc="x"></iframe>')
    spans = [f.span for f in found]
    assert len(spans) == len(set(spans))


def test_the_more_specific_rule_wins_when_two_claim_the_same_tag() -> None:
    # `iframe_element` says a dangerous tag is present. `srcdoc_attribute` says why.
    # The second is the more useful half for whoever reads the record, so rule order
    # puts it first.
    assert "srcdoc_attribute" in labels('<iframe srcdoc="<script>x</script>"></iframe>')


def test_a_span_covers_the_whole_tag_so_a_redaction_leaves_nothing_dangling() -> None:
    """Detection would be the same without this; the redacted output would not.

    A span covering only `<script` leaves `>alert(1)` in the answer. That is inert,
    because a browser has no `<script` to parse any more, but it reads as though the
    detector missed something, and the caller's users see it.
    """
    text = "Here: <script>alert(1)</script> and <img src=x onerror='go()'>."
    for finding in run(text):
        assert finding.span is not None
        matched = text[slice(*finding.span)]
        assert matched.startswith("<")
        assert matched.endswith(">"), matched


def test_an_unterminated_tag_at_the_end_of_a_truncated_output_still_matches() -> None:
    # The closing bracket is optional for exactly this case.
    assert "script_element" in labels("The answer was cut off here: <script")


# ------------------------------------------------------------------ the evasions


@pytest.mark.parametrize(
    "spelling",
    [
        "<script>alert(1)</script>",
        "<SCRIPT>alert(1)</SCRIPT>",
        "<ScRiPt>alert(1)</ScRiPt>",
        "<scr​ipt>alert(1)</script>",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "<  script >alert(1)",
    ],
)
def test_every_spelling_of_the_same_payload_is_found(spelling: str) -> None:
    assert "script_element" in labels(spelling), spelling


def test_full_width_latin_in_a_scheme_is_folded() -> None:
    # A browser resolves full-width characters in a URL scheme. This is why
    # compatibility normalisation is on for markup and off for prose.
    assert "javascript_url" in labels('<a href="ｊａｖａｓｃｒｉｐｔ:alert(1)">x</a>')


def test_a_tab_inside_a_scheme_is_folded() -> None:
    # `java&#9;script:` decodes to a tab, and browsers strip whitespace inside a scheme.
    assert "javascript_url" in labels('<a href="java&#9;script:alert(1)">x</a>')


def test_an_encoded_payload_is_reported_and_the_reason_is_deliberate() -> None:
    # Whether `&lt;script&gt;` stays inert depends on how many times the consuming
    # template unescapes, which this library cannot see. Reporting it and letting the
    # policy decide beats guessing.
    assert "script_element" in labels("&lt;script&gt;alert(1)&lt;/script&gt;")


# --------------------------------------------------- the upstream false positives


def test_a_comparison_in_prose_is_not_an_attack() -> None:
    # `bleach.clean("5 < 6")` escapes the bracket and so differs from its input, which
    # is the entire test the upstream validator performs.
    assert run("The result holds when 5 < 6 and 7 > 3.") == []


def test_an_ampersand_in_prose_is_not_an_attack() -> None:
    assert run("Please contact Sales & Support for the invoice.") == []


def test_naming_a_tag_without_writing_one_is_not_an_attack() -> None:
    assert run("Use the script element to load the library.") == []


def test_a_url_query_string_is_not_an_event_handler() -> None:
    # Without the opening-tag anchor, `on` plus letters matches `online=` and every URL
    # in the text becomes a finding.
    assert run("See https://example.com/search?online=1&onsale=true for details.") == []


def test_a_bare_svg_or_style_element_is_not_reported() -> None:
    # Dangerous only with a handler or a script inside, and both have their own rule.
    assert run("<svg viewBox='0 0 1 1'></svg>") == []
    assert run("<style>.a{color:red}</style>") == []


def test_a_mathematical_expression_is_not_reported() -> None:
    # The obsolete IE CSS vector `expression(` collides with prose about expressions.
    assert run("Evaluate the expression (x + y) for each row.") == []


def test_ordinary_markup_a_product_emits_is_not_reported() -> None:
    assert run("<p>Your balance is <strong>412 EUR</strong>.</p>") == []


# --------------------------------------------------------------------- all 26 languages

#: Ordinary sentences, one per language, each containing `<`, `>` and `&`. Those three
#: characters are what makes the upstream check fire, so this is the fixture set that
#: would have caught it.
CLEAN: dict[str, str] = {
    "en": "Sales & Support confirmed that 5 < 6 and 7 > 3 in the report.",
    "ro": "Vânzări & Suport au confirmat că 5 < 6 și 7 > 3 în raport.",
    "bg": "Продажби & Поддръжка потвърдиха, че 5 < 6 и 7 > 3 в отчета.",
    "cs": "Prodej & Podpora potvrdily, že 5 < 6 a 7 > 3 ve zprávě.",
    "da": "Salg & Support bekræftede, at 5 < 6 og 7 > 3 i rapporten.",
    "de": "Vertrieb & Support bestätigten, dass 5 < 6 und 7 > 3 im Bericht.",
    "el": "Πωλήσεις & Υποστήριξη επιβεβαίωσαν ότι 5 < 6 και 7 > 3 στην αναφορά.",
    "es": "Ventas & Soporte confirmaron que 5 < 6 y 7 > 3 en el informe.",
    "et": "Müük & Tugi kinnitasid, et 5 < 6 ja 7 > 3 aruandes.",
    "fi": "Myynti & Tuki vahvistivat, että 5 < 6 ja 7 > 3 raportissa.",
    "fr": "Ventes & Support ont confirmé que 5 < 6 et 7 > 3 dans le rapport.",
    "ga": "Dhearbhaigh Díolacháin & Tacaíocht go bhfuil 5 < 6 agus 7 > 3 sa tuairisc.",
    "hr": "Prodaja & Podrška potvrdili su da je 5 < 6 i 7 > 3 u izvješću.",
    "hu": "Az Értékesítés & Támogatás igazolta, hogy 5 < 6 és 7 > 3 a jelentésben.",
    "it": "Vendite & Supporto hanno confermato che 5 < 6 e 7 > 3 nel rapporto.",
    "lt": "Pardavimai & Palaikymas patvirtino, kad 5 < 6 ir 7 > 3 ataskaitoje.",
    "lv": "Pārdošana & Atbalsts apstiprināja, ka 5 < 6 un 7 > 3 pārskatā.",
    "mt": "Bejgħ & Appoġġ ikkonfermaw li 5 < 6 u 7 > 3 fir-rapport.",
    "nl": "Verkoop & Support bevestigden dat 5 < 6 en 7 > 3 in het rapport.",
    "pl": "Sprzedaż & Wsparcie potwierdziły, że 5 < 6 i 7 > 3 w raporcie.",
    "pt": "Vendas & Suporte confirmaram que 5 < 6 e 7 > 3 no relatório.",
    "sk": "Predaj & Podpora potvrdili, že 5 < 6 a 7 > 3 v správe.",
    "sl": "Prodaja & Podpora sta potrdili, da je 5 < 6 in 7 > 3 v poročilu.",
    "sv": "Försäljning & Support bekräftade att 5 < 6 och 7 > 3 i rapporten.",
    "tr": "Satış & Destek raporda 5 < 6 ve 7 > 3 olduğunu doğruladı.",
    "az": "Satış & Dəstək hesabatda 5 < 6 və 7 > 3 olduğunu təsdiqlədi.",
}


def test_the_fixtures_cover_every_language_the_project_claims() -> None:
    assert set(CLEAN) == CLAIMED


@pytest.mark.parametrize("code", sorted(CLEAN))
def test_ordinary_prose_in_each_language_is_not_an_attack(code: str) -> None:
    assert run(CLEAN[code]) == [], f"{code}: {CLEAN[code]}"


@pytest.mark.parametrize("code", sorted(CLEAN))
def test_a_payload_inside_prose_in_each_language_is_still_found(code: str) -> None:
    # The detector reads markup rather than prose, so a payload has to be found
    # whatever surrounds it and in whatever script.
    assert "script_element" in labels(f"{CLEAN[code]} <script>alert(1)</script>"), code


# --------------------------------------------------------------------------- plumbing


def test_the_detector_matches_the_catalogue() -> None:
    from flowx_border.detectors.catalogue import CATALOGUE

    spec = CATALOGUE["markup_injection"]
    assert (DETECTOR.id, DETECTOR.tier) == ("markup_injection", spec.tier)
    assert DETECTOR.sides == spec.sides


def test_warm_is_idempotent() -> None:
    DETECTOR.warm()
    DETECTOR.warm()
    assert "script_element" in labels("<script>x</script>")


def test_an_empty_text_is_not_an_error() -> None:
    assert run("") == []


def test_findings_never_carry_the_text() -> None:
    for finding in run("<script>alert(412)</script>"):
        assert "412" not in finding.model_dump_json()
        assert "alert" not in finding.model_dump_json()
