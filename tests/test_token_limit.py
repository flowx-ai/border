# SPDX-License-Identifier: Apache-2.0
"""Tests for the token_limit detector, most of them about the tokenizer's identity.

The counting is arithmetic and there is not much to say about it. What this detector had
to decide, and what most of these tests pin, is that the tokenizer must be named and
pinned: a count from an unspecified tokenizer cannot be reproduced from the evidence
record that reported it, and default 6 is not optional.

So a bare Hugging Face repo id is refused even though fetching one would work. That is
the only interesting decision here and it is asserted rather than described.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.multilingual import LANGUAGES as CLAIMED
from flowx_border.detectors.token_limit import (
    OVER_LIMIT_LABEL,
    UNCONFIGURED_LABEL,
    TokenLimitDetector,
    TokenLimitError,
)

CTX = Context()
CFG = DetectorConfig(on_fail="flag")


@pytest.fixture
def tokenizer_file(tmp_path: Path) -> Path:
    """A tiny real tokenizer, written here rather than downloaded.

    A word-level tokenizer over a fixed vocabulary, which is enough to count with and
    keeps the default suite offline. The detector's contract is about the tokenizer's
    identity rather than its sophistication, so a small one tests the same code path a
    32,000 piece one would.
    """
    vocab = {
        word: index
        for index, word in enumerate(["a", "b", "c", "d", "e", "f", "g", "h", "[UNK]"])
    }
    spec = {
        "version": "1.0",
        "truncation": None,
        "padding": None,
        "added_tokens": [],
        "normalizer": None,
        # WhitespaceSplit rather than Whitespace, and the difference is not cosmetic:
        # `Whitespace` is the regex \w+|[^\w\s]+, so it splits punctuation off too and
        # "l'agence" becomes three tokens. The sweep below asserts that a token is a
        # whitespace-separated word, which is only true of WhitespaceSplit. Found by the
        # French and Maltese cases failing, which was the test being wrong.
        "pre_tokenizer": {"type": "WhitespaceSplit"},
        "post_processor": None,
        "decoder": None,
        "model": {"type": "WordLevel", "vocab": vocab, "unk_token": "[UNK]"},
    }
    path = tmp_path / "tokenizer.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return path


def with_path(path: Path, limit: int) -> DetectorConfig:
    return DetectorConfig(
        on_fail="flag",
        options={"tokenizer_path": str(path), "max_tokens": limit},
    )


# --------------------------------------------------------------------- the counting


def test_a_text_under_the_limit_is_clean(tokenizer_file: Path) -> None:
    detector = TokenLimitDetector()
    detector.warm()
    assert detector.run("a b c", with_path(tokenizer_file, 5), CTX) == []


def test_a_text_over_the_limit_is_reported(tokenizer_file: Path) -> None:
    detector = TokenLimitDetector()
    found = detector.run("a b c d e f", with_path(tokenizer_file, 3), CTX)
    assert [f.label for f in found] == [OVER_LIMIT_LABEL]


def test_a_text_exactly_at_the_limit_is_clean(tokenizer_file: Path) -> None:
    """The boundary. Off by one here is a false positive on every long answer."""
    detector = TokenLimitDetector()
    assert detector.run("a b c d", with_path(tokenizer_file, 4), CTX) == []
    assert detector.run("a b c d e", with_path(tokenizer_file, 4), CTX) != []


def test_the_score_grows_with_how_far_over_it_is(tokenizer_file: Path) -> None:
    detector = TokenLimitDetector()
    just_over = detector.run("a b c", with_path(tokenizer_file, 2), CTX)
    far_over = detector.run("a b c d e f g h", with_path(tokenizer_file, 2), CTX)
    assert just_over[0].score < far_over[0].score
    assert far_over[0].score == 1.0, "at least twice the limit saturates"


def test_the_action_comes_from_the_policy(tokenizer_file: Path) -> None:
    cfg = DetectorConfig(
        on_fail="block",
        options={"tokenizer_path": str(tokenizer_file), "max_tokens": 1},
    )
    found = TokenLimitDetector().run("a b c", cfg, CTX)
    assert [f.action for f in found] == ["block"]


# ------------------------------------------------------------ the tokenizer's identity


def test_the_finding_names_the_tokenizer_that_produced_the_count(
    tokenizer_file: Path,
) -> None:
    """Without this the count is a number with no provenance.

    `EvidenceRecord` exists so somebody who was not there can check a decision later,
    and a token count is meaningless without knowing which tokenizer produced it.
    """
    found = TokenLimitDetector().run("a b c", with_path(tokenizer_file, 1), CTX)
    assert found[0].model_id == "tokenizer.json"
    assert found[0].model_revision is not None
    assert found[0].model_revision.startswith("local:")


def test_the_local_revision_changes_when_the_file_changes(
    tokenizer_file: Path,
) -> None:
    """The revision is the file's hash, so editing the tokenizer changes the record.

    This is the same rule `models/registry.py` applies to weights under a local
    override, and for the same reason: a record claiming one identity for bytes that
    have since changed would be a forgery rather than a stale label.
    """
    first = TokenLimitDetector().run("a b c", with_path(tokenizer_file, 1), CTX)
    spec = json.loads(tokenizer_file.read_text(encoding="utf-8"))
    spec["model"]["vocab"]["extra"] = len(spec["model"]["vocab"])
    tokenizer_file.write_text(json.dumps(spec), encoding="utf-8")
    second = TokenLimitDetector().run("a b c", with_path(tokenizer_file, 1), CTX)
    assert first[0].model_revision != second[0].model_revision


def test_a_bare_repo_id_is_refused_with_the_reason() -> None:
    """The one decision in this detector worth arguing about, asserted.

    Fetching a tokenizer from the hub would work and entry 1 permits a fetch that
    caches. It is refused because a repo id without a revision names a moving target:
    the count it produces today is not the count it produces after the repo moves, and
    the evidence record could not tell the difference.
    """
    cfg = DetectorConfig(
        on_fail="flag",
        options={"tokenizer_model": "openai-community/gpt2", "max_tokens": 10},
    )
    with pytest.raises(TokenLimitError, match="moving target"):
        TokenLimitDetector().run("a b c", cfg, CTX)


def test_a_pinned_registry_id_is_accepted() -> None:
    """The other half: an id that carries a commit is fine, and reports that commit."""
    from flowx_border.models.registry import MODELS

    model_id = "piiguard"
    if model_id not in MODELS:
        pytest.skip("piiguard is not in the registry")
    cfg = DetectorConfig(
        on_fail="flag",
        options={"tokenizer_model": model_id, "max_tokens": 1},
    )
    try:
        found = TokenLimitDetector().run("one two three four", cfg, CTX)
    except Exception as error:  # pragma: no cover - depends on a cached artifact
        pytest.skip(f"piiguard's tokenizer is not available locally: {error}")
    assert found[0].model_id == model_id
    assert found[0].model_revision == MODELS[model_id].revision


def test_a_missing_tokenizer_file_is_refused(tmp_path: Path) -> None:
    cfg = with_path(tmp_path / "absent.json", 10)
    with pytest.raises(TokenLimitError, match="is not a file"):
        TokenLimitDetector().run("a b c", cfg, CTX)


def test_naming_both_a_path_and_a_model_is_refused(tokenizer_file: Path) -> None:
    cfg = DetectorConfig(
        on_fail="flag",
        options={
            "tokenizer_path": str(tokenizer_file),
            "tokenizer_model": "piiguard",
            "max_tokens": 10,
        },
    )
    with pytest.raises(TokenLimitError, match="Name one"):
        TokenLimitDetector().run("a b c", cfg, CTX)


def test_the_ambiguous_tokenizer_option_is_refused(tokenizer_file: Path) -> None:
    """`tokenizer` could mean a file or a repo, so it is refused not guessed."""
    cfg = DetectorConfig(
        on_fail="flag",
        options={"tokenizer": str(tokenizer_file), "max_tokens": 10},
    )
    with pytest.raises(TokenLimitError, match="ambiguous"):
        TokenLimitDetector().run("a b c", cfg, CTX)


# ------------------------------------------------------- saying so rather than passing


def test_no_configuration_at_all_is_reported() -> None:
    found = TokenLimitDetector().run("a b c", CFG, CTX)
    assert [f.label for f in found] == [UNCONFIGURED_LABEL]
    # log rather than the policy's action: an operator who enabled the detector and
    # forgot the limit should be told, not have every request blocked.
    assert found[0].action == "log"


def test_a_limit_with_no_tokenizer_is_reported(tokenizer_file: Path) -> None:
    cfg = DetectorConfig(on_fail="flag", options={"max_tokens": 10})
    found = TokenLimitDetector().run("a b c", cfg, CTX)
    assert [f.label for f in found] == [UNCONFIGURED_LABEL]


def test_a_tokenizer_with_no_limit_is_reported(tokenizer_file: Path) -> None:
    cfg = DetectorConfig(
        on_fail="flag", options={"tokenizer_path": str(tokenizer_file)}
    )
    found = TokenLimitDetector().run("a b c", cfg, CTX)
    assert [f.label for f in found] == [UNCONFIGURED_LABEL]


def test_a_zero_limit_is_refused(tokenizer_file: Path) -> None:
    cfg = with_path(tokenizer_file, 0)
    with pytest.raises(TokenLimitError, match="at least 1"):
        TokenLimitDetector().run("a b c", cfg, CTX)


# ------------------------------------------------------------- the languages


#: One sentence per language, all counted with the same tokenizer.
#: What this checks is that counting does not depend on the script. A tokenizer whose
#: pre-tokenizer split only on ASCII whitespace, or a count that went through a byte
#: length by mistake, would give a different answer for Greek or Bulgarian than for
#: English at the same word count, and the limit would then mean something different per
#: language without anyone noticing.
SENTENCES: dict[str, str] = {
    "en": "the branch opens at nine in the morning",
    "ro": "sucursala se deschide la nouă dimineața",
    "bg": "клонът отваря в девет сутринта",
    "cs": "filiálka otevírá v devět ráno",
    "da": "filialen åbner klokken ni om morgenen",
    "de": "die Filiale öffnet um neun Uhr morgens",
    "el": "το κατάστημα ανοίγει στις εννέα το πρωί",
    "es": "la sucursal abre a las nueve de la mañana",
    "et": "kontor avatakse hommikul kell üheksa",
    "fi": "konttori avataan yhdeksältä aamulla",
    "fr": "l'agence ouvre à neuf heures du matin",
    "ga": "osclaíonn an brainse ar a naoi ar maidin",
    "hr": "poslovnica se otvara u devet ujutro",
    "hu": "a fiók reggel kilenc órakor nyit",
    "it": "la filiale apre alle nove del mattino",
    "lt": "skyrius atidaromas devintą valandą ryto",
    "lv": "filiāle tiek atvērta deviņos no rīta",
    "mt": "il-fergha tiftah fid-disgha ta filghodu",
    "nl": "het filiaal opent om negen uur",
    "pl": "oddział otwiera się o dziewiątej rano",
    "pt": "a agência abre às nove da manhã",
    "sk": "filiálka otvára o deviatej ráno",
    "sl": "poslovalnica se odpre ob devetih zjutraj",
    "sv": "kontoret öppnar klockan nio på morgonen",
    "tr": "şube sabah dokuzda açılıyor",
    "az": "filial səhər doqquzda açılır",
}


def test_the_fixtures_cover_every_language_the_project_claims() -> None:
    assert set(SENTENCES) == CLAIMED


@pytest.mark.parametrize("code", sorted(SENTENCES))
def test_the_count_is_the_word_count_in_every_script(
    code: str, tokenizer_file: Path
) -> None:
    """With a whitespace pre-tokenizer, tokens are words, in every script.

    Which is the property that matters: if this held for Latin script and not for Greek,
    the same limit would mean two different things depending on the language, and
    nothing in the detector would say so.
    """
    sentence = SENTENCES[code]
    words = len(sentence.split())
    detector = TokenLimitDetector()
    assert detector.run(sentence, with_path(tokenizer_file, words), CTX) == [], code
    over = detector.run(sentence, with_path(tokenizer_file, words - 1), CTX)
    assert [f.label for f in over] == [OVER_LIMIT_LABEL], code


# -------------------------------------------------------------- catalogue agreement


def test_the_detector_matches_the_catalogue() -> None:
    from flowx_border.detectors.catalogue import CATALOGUE, CORE

    detector = TokenLimitDetector()
    spec = CATALOGUE[detector.id]
    assert spec.tier == detector.tier
    assert spec.sides == detector.sides
    assert not spec.requires, "tokenizers is in the base install, so it needs nothing"
    assert detector.id in CORE


def test_it_is_reachable_through_the_registry() -> None:
    from flowx_border.registry import implemented_detectors

    assert "token_limit" in implemented_detectors()
