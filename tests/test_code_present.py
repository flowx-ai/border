# SPDX-License-Identifier: Apache-2.0
"""Tests for the code_present detector, and for the false positive it cannot avoid.

The detector answers "is there code here" with a list of shapes rather than a judgement,
so most of these tests are about one shape each. The two that matter most are the ones
about the margin: prose that discusses programming trips a keyword rule, and this
detector reports what fired rather than pretending to know the difference.

That is the same contract `sql_injection` has and the same one `summary_support` has. A
rule that says plainly what it matched is worth more than a rule that implies judgement
it does not have.
"""

from __future__ import annotations

import pytest

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.code_present import (
    DENSITY_LABEL,
    SIGNALS,
    TRUNCATED_LABEL,
    CodePresentDetector,
    CodePresentError,
)
from flowx_border.detectors.multilingual import LANGUAGES as CLAIMED

CFG = DetectorConfig(on_fail="flag")
CTX = Context()


@pytest.fixture
def detector() -> CodePresentDetector:
    found = CodePresentDetector()
    found.warm()
    return found


def labels(text: str, cfg: DetectorConfig = CFG) -> list[str]:
    found = CodePresentDetector()
    found.warm()
    return [f.label for f in found.run(text, cfg, CTX)]


# ------------------------------------------------------------------- one shape each


def test_a_fenced_block_is_found(detector: CodePresentDetector) -> None:
    text = "Here is the fix:\n```python\nvalue = compute(1)\n```\nThat should do it."
    assert "code_fence" in labels(text)


def test_a_tilde_fence_is_found_too() -> None:
    assert "code_fence" in labels("Try this:\n~~~\nx = 1\n~~~\n")


def test_a_shebang_is_found() -> None:
    assert "code_shebang" in labels("#!/usr/bin/env python3\nprint(1)\n")


def test_a_python_definition_is_found() -> None:
    assert "code_definition" in labels("def handle(request):\n    return None\n")


def test_a_java_method_is_found() -> None:
    text = "public static void main(String[] args) {\n    return;\n}"
    assert "code_definition" in labels(text)


def test_a_rust_and_a_go_function_are_found() -> None:
    assert "code_definition" in labels("fn main() {\n    let x = 1;\n}")
    assert "code_definition" in labels("func main() {\n\tx := 1\n}")


def test_an_import_is_found() -> None:
    assert "code_import" in labels("from pathlib import Path\n")
    assert "code_import" in labels("import os\n")
    assert "code_import" in labels("#include <stdio.h>\n")


def test_a_script_tag_is_found() -> None:
    assert "code_script_tag" in labels("<script>alert(1)</script>")
    assert "code_script_tag" in labels("<?php echo 1; ?>")


def test_a_shell_invocation_is_found() -> None:
    assert "code_shell" in labels("Run this:\n$ pip install flowx-border\n")
    assert "code_shell" in labels("Then:\n$ docker compose up\n")


def test_the_span_points_at_what_matched() -> None:
    text = "Some prose first. Then:\n```\nx = 1\n```"
    found = CodePresentDetector().run(text, CFG, CTX)
    fence = next(f for f in found if f.label == "code_fence")
    start, end = fence.span or (0, 0)
    assert text[start:end].strip().startswith("```")


def test_the_action_comes_from_the_policy() -> None:
    cfg = DetectorConfig(on_fail="redact")
    found = CodePresentDetector().run("def f(x):\n    pass\n", cfg, CTX)
    assert {f.action for f in found} == {"redact"}


# ------------------------------------------------- ordinary prose is not code


def test_plain_prose_reports_nothing() -> None:
    text = (
        "Your account balance is 412 EUR. The branch on the high street opens at nine "
        "and closes at five, and the cash machine is available at all hours."
    )
    assert labels(text) == []


def test_prose_that_merely_mentions_a_keyword_is_not_code() -> None:
    """The whole reason the patterns demand punctuation rather than words.

    Every sentence here contains a word that appears in a pattern above. None of them is
    code, and a rule keyed on the bare word would report all four.
    """
    for sentence in (
        "Please import the statement into your accounting software.",
        "The class of account you hold determines the interest rate.",
        "We package your documents and send them by post.",
        "Our function is to keep your money safe.",
    ):
        assert labels(sentence) == [], sentence


def test_a_word_that_looks_like_a_definition_without_the_parenthesis_is_not_code() -> (
    None
):
    # "def" is a French and Romanian word fragment and an English abbreviation. What
    # makes it a definition is the name and the parenthesis after it.
    assert labels("def is short for definition in this glossary.") == []


# ------------------------------------------ the false positive it cannot avoid


def test_a_definition_inside_a_sentence_is_not_reported() -> None:
    """The cost of anchoring every pattern at the start of a line, stated as a test.

    This sentence contains a real Python definition and the detector says nothing,
    because `code_definition` requires the construct to begin a line. That is the trade
    and it is deliberate: the anchor is what keeps the four prose cases above clean, and
    prose that quotes a fragment inline is far more common than code that starts
    mid-sentence.

    Anyone who needs the inline case has two honest options, and neither is loosening
    this pattern: enable `punctuation_density`, or ask the caller to fence their code.
    Dropping the anchor would report "Our function is to keep your money safe" as a
    function definition, which was measured while writing this file.
    """
    text = "To define a handler, write def handle(request): and return a response."
    assert labels(text) == []


def test_a_fenced_block_inside_prose_about_code_does_report() -> None:
    """Which is the same margin from the other side, and why the fence signal exists.

    An answer that explains something and then shows it is both prose and code. The
    detector reports the code shape; whether an answer about programming may contain
    programming is a policy question, and the policy has what it needs to decide.
    """
    text = (
        "To define a handler, write:\n```\ndef handle(request):\n    return None\n```"
    )
    found = labels(text)
    assert "code_fence" in found
    assert "code_definition" in found


def test_a_table_of_figures_is_not_reported_unless_density_is_switched_on() -> None:
    """Why the density signal is off by default.

    This line is punctuation-heavy and is not code. With the default configuration
    nothing fires; a caller who wants recall over precision switches the signal on and
    is told which one fired, rather than getting it folded into a single score.
    """
    table = "| 2024 | 1,204.55 | 3.1% | +0.4 |"
    assert labels(table) == []

    dense = DetectorConfig(on_fail="flag", options={"punctuation_density": True})
    assert labels(table, dense) == [DENSITY_LABEL]


# ------------------------------------------------------------------ configuration


def test_the_signals_are_ordered_strongest_first() -> None:
    confidences = [signal.confidence for signal in SIGNALS]
    assert confidences == sorted(confidences, reverse=True)
    assert confidences[0] == 1.0, "a fence is the one shape prose never has"


def test_min_confidence_filters_the_weaker_signals() -> None:
    text = "Run this:\n$ pip install flowx-border\n"
    assert "code_shell" in labels(text)
    strict = DetectorConfig(on_fail="flag", options={"min_confidence": 0.9})
    assert labels(text, strict) == []


def test_a_policy_can_select_individual_signals() -> None:
    text = "```\nimport os\n```"
    only_fence = DetectorConfig(on_fail="flag", options={"signals": ["code_fence"]})
    assert labels(text, only_fence) == ["code_fence"]


def test_an_unknown_signal_name_is_refused_rather_than_ignored() -> None:
    """A misspelled signal would switch a check off and say nothing.

    Which is the silent no-op this library treats as a vulnerability. The error names
    the known signals so the fix does not need the source.
    """
    cfg = DetectorConfig(on_fail="flag", options={"signals": ["code_fenc"]})
    with pytest.raises(CodePresentError, match="code_fenc"):
        CodePresentDetector().run("```\nx\n```", cfg, CTX)


def test_an_out_of_range_min_confidence_is_refused() -> None:
    cfg = DetectorConfig(on_fail="flag", options={"min_confidence": 1.5})
    with pytest.raises(CodePresentError, match="between 0 and 1"):
        CodePresentDetector().run("def f(x):\n    pass\n", cfg, CTX)


def test_truncation_is_reported_rather_than_silent() -> None:
    cfg = DetectorConfig(on_fail="flag", options={"max_chars": 40})
    text = "a" * 100 + "\n```\nx = 1\n```"
    found = labels(text, cfg)
    assert TRUNCATED_LABEL in found
    # And the fence past the cut is genuinely not reported, which is what makes the
    # truncation finding load-bearing rather than decorative.
    assert "code_fence" not in found


def test_an_empty_input_produces_nothing() -> None:
    assert labels("") == []
    assert labels("   \n\t\n") == []


# ------------------------------------------------------------- the languages


#: The same Python snippet inside prose in each of the 26 languages, and the same prose
#: without it.
#: What this checks is narrower than it looks, and saying so is the point: the detector
#: knows a handful of programming languages, not 26 human ones. What has to hold is that
#: the human language around a snippet does not change whether the snippet is found, and
#: that ordinary prose in any of the 26 is not mistaken for code. A pattern anchored on
#: an ASCII word boundary can fail the second half in a script that does not use ASCII,
#: which is why the negative case is here per language rather than once in English.
PROSE: dict[str, str] = {
    "en": "Your balance is 412 EUR and the branch opens at nine in the morning.",
    "ro": "Soldul este de 412 EUR și sucursala se deschide la nouă dimineața.",
    "bg": "Салдото ви е 412 EUR и клонът отваря в девет сутринта.",
    "cs": "Váš zůstatek je 412 EUR a filiálka otevírá v devět ráno.",
    "da": "Din saldo er 412 EUR, og filialen åbner klokken ni om morgenen.",
    "de": "Ihr Guthaben beträgt 412 EUR und die Filiale öffnet um neun Uhr.",
    "el": "Το υπόλοιπό σας είναι 412 EUR και το κατάστημα ανοίγει στις εννέα.",
    "es": "Su saldo es de 412 EUR y la sucursal abre a las nueve de la mañana.",
    "et": "Teie jääk on 412 EUR ja kontor avatakse hommikul kell üheksa.",
    "fi": "Saldosi on 412 EUR ja konttori avataan yhdeksältä aamulla.",
    "fr": "Votre solde est de 412 EUR et l'agence ouvre à neuf heures.",
    "ga": "Is é 412 EUR do iarmhéid agus osclaíonn an brainse ar a naoi.",
    "hr": "Vaše stanje je 412 EUR, a poslovnica se otvara u devet ujutro.",
    "hu": "Az egyenlege 412 EUR, és a fiók reggel kilenckor nyit.",
    "it": "Il tuo saldo è di 412 EUR e la filiale apre alle nove del mattino.",
    "lt": "Jūsų likutis yra 412 EUR, o skyrius atidaromas devintą ryto.",
    "lv": "Jūsu atlikums ir 412 EUR, un filiāle tiek atvērta deviņos.",
    "mt": "Il-bilanc tieghek huwa 412 EUR u l-fergha tiftah fid-disgha.",
    "nl": "Uw saldo is 412 EUR en het filiaal opent om negen uur.",
    "pl": "Twoje saldo wynosi 412 EUR, a oddział otwiera się o dziewiątej.",
    "pt": "O seu saldo é de 412 EUR e a agência abre às nove da manhã.",
    "sk": "Váš zostatok je 412 EUR a filiálka otvára o deviatej ráno.",
    "sl": "Vaše stanje je 412 EUR in poslovalnica se odpre ob devetih.",
    "sv": "Ditt saldo är 412 EUR och kontoret öppnar klockan nio.",
    "tr": "Bakiyeniz 412 EUR ve şube sabah dokuzda açılıyor.",
    "az": "Balansınız 412 EUR və filial səhər doqquzda açılır.",
}

SNIPPET = "```python\ndef balance(account):\n    return account.total\n```"


def test_the_fixtures_cover_every_language_the_project_claims() -> None:
    assert set(PROSE) == CLAIMED


@pytest.mark.parametrize("code", sorted(PROSE))
def test_a_snippet_is_found_whatever_the_surrounding_language(code: str) -> None:
    found = labels(f"{PROSE[code]}\n\n{SNIPPET}\n")
    assert "code_fence" in found, code
    assert "code_definition" in found, code


@pytest.mark.parametrize("code", sorted(PROSE))
def test_ordinary_prose_in_each_language_is_not_code(code: str) -> None:
    """Which is what gives the sweep above its meaning.

    A detector that reported everything would pass all 26 positive cases. What has to
    hold is that the prose alone is clean in every one of the 26.
    """
    assert labels(PROSE[code]) == [], code


# -------------------------------------------------------------- catalogue agreement


def test_the_detector_matches_the_catalogue() -> None:
    from flowx_border.detectors.catalogue import CATALOGUE, CORE

    detector = CodePresentDetector()
    spec = CATALOGUE[detector.id]
    assert spec.tier == detector.tier
    assert spec.sides == detector.sides
    assert not spec.requires, "it is a regex over text, so it needs nothing"
    assert detector.id in CORE


def test_it_is_reachable_through_the_registry() -> None:
    from flowx_border.registry import implemented_detectors

    assert "code_present" in implemented_detectors()
