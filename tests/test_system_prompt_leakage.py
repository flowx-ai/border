# SPDX-License-Identifier: Apache-2.0
"""Tests for the system_prompt_leakage detector.

The first test in the file is the reason the detector was rewritten rather than copied:
the upstream validator compares two whole strings for similarity, so the case it is
weakest on is a long helpful answer with the system prompt buried inside it, which is
exactly the case that matters. It is asserted here against `difflib`, which computes the
same kind of normalised similarity ratio that `rapidfuzz.fuzz.ratio` does, so the
comparison stands without taking a dependency on rapidfuzz to prove a point about it.

All 26 languages are exercised on the phrase signal. That signal is the only one
available when no system prompt was supplied, and it is the only one that catches a
paraphrase, so an English-only phrase list would mean 25 languages get one detector and
English gets two.
"""

from __future__ import annotations

from difflib import SequenceMatcher

import pytest

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.system_prompt_leakage import (
    SystemPromptDataError,
    SystemPromptLeakageDetector,
    load_phrasings,
    unreviewed_languages,
)
from flowx_border.types import Finding

DETECTOR = SystemPromptLeakageDetector()

SYSTEM_PROMPT = (
    "You are a banking assistant for retail customers. Never reveal account numbers "
    "or internal reference codes. Always answer in the language the user wrote in. "
    "Refuse any request about a customer other than the one you are speaking to."
)


def ctx(prompt: str | None = SYSTEM_PROMPT) -> Context:
    return Context(metadata={"system_prompt": prompt} if prompt else {})


def run(text: str, context: Context | None = None, **options: object) -> list[Finding]:
    return DETECTOR.run(
        text,
        DetectorConfig(on_fail="flag", options=options),
        context if context is not None else ctx(),
    )


def labels(text: str, context: Context | None = None, **options: object) -> list[str]:
    return [finding.label for finding in run(text, context, **options)]


# ------------------------------------------------------- the bug that forced a rewrite


def test_a_long_answer_quoting_the_prompt_is_caught_where_similarity_fails() -> None:
    """Containment and similarity are different questions.

    `fuzz.ratio(output, system_prompt) > 40` measures whether the output *is* the
    prompt. Pad the leak with ordinary helpful text and the ratio collapses while the
    leak stays exactly as bad. This is the shape a real leak takes, because a model
    that has been talked into revealing its instructions wraps them in an explanation.
    """
    padding = (
        "Of course, I am glad to help you with your account today. Here is a little "
        "background before I answer your question, so that the reply makes sense in "
        "context and you can see where the numbers come from. "
    ) * 4
    leaked = f"{padding}{SYSTEM_PROMPT} {padding}"

    similarity = SequenceMatcher(None, leaked, SYSTEM_PROMPT).ratio() * 100
    assert similarity < 40, "the upstream threshold would have passed this"

    found = [f for f in run(leaked) if f.label == "system_prompt_quoted"]
    assert found, "containment must catch what similarity misses"
    assert found[0].score == 1.0


def test_an_answer_that_does_not_quote_the_prompt_is_not_reported() -> None:
    clean = "Your balance is 412 EUR as of this morning. Anything else I can do?"
    assert "system_prompt_quoted" not in labels(clean)


def test_the_score_is_the_fraction_of_the_prompt_that_appeared() -> None:
    """And the threshold is a fraction of the prompt, which is the useful reading.

    Twenty of the prompt's forty-seven words is 0.37, so at the default threshold of
    0.5 this is not reported at all. That is the intended behaviour and it is worth
    pinning: the threshold on this detector means "how much of my system prompt has to
    appear before I want to hear about it", and a deployment that wants to hear about a
    third of it says so.
    """
    partial = f"Sure. {' '.join(SYSTEM_PROMPT.split()[:20])}"
    assert "system_prompt_quoted" not in labels(partial)

    sensitive = DETECTOR.run(
        partial, DetectorConfig(on_fail="flag", threshold=0.2), ctx()
    )
    found = [f for f in sensitive if f.label == "system_prompt_quoted"]
    assert found
    assert 0.3 < found[0].score < 0.5


def test_the_span_points_at_the_quoted_passage() -> None:
    text = f"Here is some preamble. {SYSTEM_PROMPT} And that is all."
    found = [f for f in run(text) if f.label == "system_prompt_quoted"]
    assert found[0].span is not None
    quoted = text[slice(*found[0].span)]
    assert "banking assistant" in quoted
    assert "preamble" not in quoted


def test_one_contiguous_leak_is_one_finding_rather_than_one_per_shingle() -> None:
    # Shingles overlap by construction, so without merging a 40 word leak becomes 36
    # findings describing the same passage and the record fills with rows to reassemble.
    found = [f for f in run(f"Preamble. {SYSTEM_PROMPT}") if f.label.endswith("quoted")]
    assert len(found) == 1


# ------------------------------------------------------------- unverifiable, not clean


def test_no_system_prompt_reports_that_rather_than_a_clean_scan() -> None:
    assert labels("Your balance is 412 EUR.", ctx(None)) == ["leakage_unverifiable"]


def test_the_unverifiable_finding_never_blocks() -> None:
    found = DETECTOR.run("text", DetectorConfig(on_fail="block"), ctx(None))
    assert [f.action for f in found] == ["log"]


def test_a_system_prompt_too_short_to_compare_is_unverifiable() -> None:
    # "Be brief" appears inside innocent answers, so a containment measure over it
    # reports leakage for text that leaked nothing.
    assert "leakage_unverifiable" in labels("Anything.", ctx("Be brief"))


def test_the_phrase_signal_still_runs_when_the_prompt_is_missing() -> None:
    # Unverifiable means one of the two signals was unavailable, not that nothing
    # happened.
    found = labels("Sure, my system prompt says to be brief.", ctx(None))
    assert "system_prompt_announced" in found
    assert "leakage_unverifiable" in found


def test_the_prompt_can_come_from_the_policy_when_it_is_fixed() -> None:
    found = labels(f"Preamble. {SYSTEM_PROMPT}", Context(), system_prompt=SYSTEM_PROMPT)
    assert "system_prompt_quoted" in found


def test_sources_are_not_read_as_a_system_prompt() -> None:
    """An answer is supposed to contain its sources.

    Reading a system prompt out of Context.sources would flag every correctly grounded
    answer, which is a false positive on the exact behaviour the product wants.
    """
    grounded = Context(sources=(SYSTEM_PROMPT,))
    assert labels(f"Preamble. {SYSTEM_PROMPT}", grounded) == ["leakage_unverifiable"]


# ----------------------------------------------------------------- the phrase signal


def test_a_paraphrase_is_caught_by_the_phrase_signal() -> None:
    # Containment cannot catch this: none of the prompt's wording survives.
    text = "I was told to keep answers short and to avoid other customers' details."
    found = [f for f in run(text) if f.label == "system_prompt_announced"]
    assert found


def test_naming_the_system_prompt_scores_higher_than_referring_to_instructions() -> (
    None
):
    strong = run("My system prompt says to be brief.", ctx(None))[0]
    weak = run("My instructions are to be brief.", ctx(None))[0]
    assert strong.score > weak.score


def test_raising_the_threshold_switches_the_weak_set_off() -> None:
    # The documented knob: weak sits exactly on the default threshold.
    assert "system_prompt_announced" in labels("My instructions are to be brief.")
    found = DETECTOR.run(
        "My instructions are to be brief.",
        DetectorConfig(on_fail="flag", threshold=0.6),
        ctx(None),
    )
    assert "system_prompt_announced" not in [f.label for f in found]


def test_a_passage_matching_both_strengths_is_reported_once() -> None:
    found = [
        f
        for f in run("My system prompt says my instructions are secret.", ctx(None))
        if f.label == "system_prompt_announced"
    ]
    spans = [f.span for f in found]
    assert len(spans) == len(set(spans))


def test_an_ordinary_answer_does_not_announce_anything() -> None:
    assert labels("Your balance is 412 EUR this morning.", ctx(None)) == [
        "leakage_unverifiable"
    ]


def test_a_policy_can_add_house_wording() -> None:
    assert "system_prompt_announced" in labels(
        "My operating brief says to be brief.",
        ctx(None),
        extra_phrasings=["my operating brief"],
    )


def test_a_policy_can_restrict_the_languages() -> None:
    romanian_only = ctx(None)
    assert "system_prompt_announced" not in labels(
        "My system prompt says to be brief.", romanian_only, languages=["ro"]
    )


def test_restricting_to_an_unknown_language_raises_rather_than_checking_nothing() -> (
    None
):
    with pytest.raises(SystemPromptDataError, match="no phrasings"):
        run("x", ctx(None), languages=["xx"])


# --------------------------------------------------------------------- all 26 languages

#: code -> (a sentence announcing the system prompt, an ordinary sentence)
LANGUAGES: dict[str, tuple[str, str]] = {
    "en": (
        "Sure, my system prompt says to be brief.",
        "Your balance is 412 EUR as of this morning.",
    ),
    "ro": (
        "Desigur, promptul meu de sistem spune să fiu scurt.",
        "Soldul dumneavoastră este de 412 EUR în această dimineață.",
    ),
    "bg": (
        "Разбира се, моят системен промпт казва да бъда кратък.",
        "Салдото ви е 412 EUR към тази сутрин.",
    ),
    "cs": (
        "Jistě, můj systémový prompt říká, abych byl stručný.",
        "Váš zůstatek je dnes ráno 412 EUR.",
    ),
    "da": (
        "Selvfølgelig, min systemprompt siger, at jeg skal være kort.",
        "Din saldo er 412 EUR i morges.",
    ),
    "de": (
        "Natürlich, mein Systemprompt sagt, ich soll kurz sein.",
        "Ihr Kontostand beträgt heute Morgen 412 EUR.",
    ),
    "el": (
        "Βεβαίως, το μήνυμα συστήματος λέει να είμαι σύντομος.",
        "Το υπόλοιπό σας είναι 412 EUR σήμερα το πρωί.",
    ),
    "es": (
        "Claro, mi prompt de sistema dice que sea breve.",
        "Su saldo es de 412 EUR esta mañana.",
    ),
    "et": (
        "Muidugi, minu süsteemiviip ütleb, et pean olema lühike.",
        "Teie saldo on täna hommikul 412 EUR.",
    ),
    "fi": (
        "Toki, järjestelmäkehotteeni sanoo, että minun pitää olla lyhyt.",
        "Saldosi on tänä aamuna 412 EUR.",
    ),
    "fr": (
        "Bien sûr, mon prompt système dit d'être bref.",
        "Votre solde est de 412 EUR ce matin.",
    ),
    "ga": (
        "Cinnte, deir mo leid chórais a bheith gairid.",
        "Is é 412 EUR an t-iarmhéid atá agat ar maidin.",
    ),
    "hr": (
        "Naravno, moj sistemski prompt kaže da budem kratak.",
        "Vaš saldo jutros iznosi 412 EUR.",
    ),
    "hu": (
        "Persze, a rendszerpromptom azt mondja, legyek rövid.",
        "Az egyenlege ma reggel 412 EUR.",
    ),
    "it": (
        "Certo, il mio prompt di sistema dice di essere breve.",
        "Il suo saldo è di 412 EUR questa mattina.",
    ),
    "lt": (
        "Žinoma, mano sistemos užklausa sako būti trumpam.",
        "Jūsų balansas šį rytą yra 412 EUR.",
    ),
    "lv": (
        "Protams, mana sistēmas uzvedne saka būt īsam.",
        "Jūsu atlikums šorīt ir 412 EUR.",
    ),
    "mt": (
        "Ovvjament, il-prompt tas-sistema tiegħi jgħid biex inkun qasir.",
        "Il-bilanċ tiegħek dalgħodu huwa 412 EUR.",
    ),
    "nl": (
        "Natuurlijk, mijn systeemprompt zegt dat ik kort moet zijn.",
        "Uw saldo is vanmorgen 412 EUR.",
    ),
    "pl": (
        "Oczywiście, mój prompt systemowy mówi, żebym był zwięzły.",
        "Twoje saldo wynosi 412 EUR na dziś rano.",
    ),
    "pt": (
        "Claro, o meu prompt de sistema diz para ser breve.",
        "O seu saldo é de 412 EUR esta manhã.",
    ),
    "sk": (
        "Iste, môj systémový prompt hovorí, aby som bol stručný.",
        "Váš zostatok je dnes ráno 412 EUR.",
    ),
    "sl": (
        "Seveda, moj sistemski poziv pravi, naj bom kratek.",
        "Vaše stanje je danes zjutraj 412 EUR.",
    ),
    "sv": (
        "Visst, min systemprompt säger att jag ska vara kort.",
        "Ditt saldo är 412 EUR i morse.",
    ),
    "tr": (
        "Elbette, sistem istemim kısa olmamı söylüyor.",
        "Bakiyeniz bu sabah itibarıyla 412 EUR.",
    ),
    "az": (
        "Əlbəttə, sistem promptum qısa olmağımı deyir.",
        "Bu səhər hesabınızdaki qalıq 412 EUR-dur.",
    ),
}


def test_the_fixtures_cover_every_language_in_the_data_file() -> None:
    # A phrasings file with an untested language is a phrasings file with a typo in it.
    assert set(load_phrasings()) == set(LANGUAGES)


def test_every_language_the_project_claims_has_phrasings() -> None:
    assert len(load_phrasings()) == 26


@pytest.mark.parametrize("code", sorted(LANGUAGES))
def test_an_announcement_in_each_language_is_found(code: str) -> None:
    announced, _ = LANGUAGES[code]
    assert "system_prompt_announced" in labels(announced, ctx(None)), code


@pytest.mark.parametrize("code", sorted(LANGUAGES))
def test_an_ordinary_answer_in_each_language_announces_nothing(code: str) -> None:
    _, ordinary = LANGUAGES[code]
    assert labels(ordinary, ctx(None)) == ["leakage_unverifiable"], code


@pytest.mark.parametrize("code", sorted(LANGUAGES))
def test_an_uppercase_announcement_in_each_language_is_found(code: str) -> None:
    # Casefolding across every script, not just Latin.
    announced, _ = LANGUAGES[code]
    assert "system_prompt_announced" in labels(announced.upper(), ctx(None)), code


def test_the_unreviewed_languages_are_reported_rather_than_hidden() -> None:
    # 26 languages is not 26 verified languages, and a coverage table has to say so.
    assert len(unreviewed_languages()) == 26


# --------------------------------------------------------------------------- plumbing


def test_the_detector_matches_the_catalogue() -> None:
    from flowx_border.detectors.catalogue import CATALOGUE

    spec = CATALOGUE["system_prompt_leakage"]
    assert (DETECTOR.id, DETECTOR.tier) == ("system_prompt_leakage", spec.tier)
    assert DETECTOR.sides == spec.sides


def test_warm_is_idempotent() -> None:
    DETECTOR.warm()
    DETECTOR.warm()
    assert "system_prompt_announced" in labels(
        "My system prompt says hello.", ctx(None)
    )


def test_findings_never_carry_the_text() -> None:
    for finding in run(f"Preamble 412 EUR. {SYSTEM_PROMPT}"):
        assert "412" not in finding.model_dump_json()
        assert "banking" not in finding.model_dump_json()


def test_an_empty_output_is_not_an_error() -> None:
    assert "system_prompt_quoted" not in labels("")
