# SPDX-License-Identifier: Apache-2.0
"""`topic_scope`'s typed engine, against the real `flowxai/topic-scope-v2` weights.

The engine is a port: the model was trained and evaluated in the training repository,
and what this library can get wrong is the path from text to the head's inputs
(tokenizer, per-piece truncation, packing, the none offset, the temperature). So the
central test runs the library's own engine over 78 test rows, three per language in all
26, and compares its answers with the ones the training run gave for the same rows. A
disagreement there is a porting bug; a wrong answer the run also gave is the model, and
is counted separately.

The fixtures come from `scripts/topic_scope_v2_library.py` in the training repository,
from the run's saved logits. They are unseen-type rows: taxonomies from deployment types
the model never trained on.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

os.environ.setdefault("HF_HUB_OFFLINE", "1")

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.multilingual import LANGUAGES
from flowx_border.detectors.topic_scope import (
    NONE_LABEL,
    SHORTLIST_LABEL,
    TopicScopeDetector,
    TopicScopeError,
)
from flowx_border.detectors.topic_scope_typed import MAX_OPTIONS

FIXTURES = (
    Path(__file__).parent / "fixtures" / "topic_scope" / "typed_26_languages.json"
)
ROWS: list[dict[str, Any]] = json.loads(FIXTURES.read_text(encoding="utf-8"))["rows"]

#: Rows allowed to differ from the training run. The run's logits came from a GPU in
#: bf16 and the library runs the int8 encoder on a CPU, so a row whose top two options
#: sit a hair apart may swap. Two of 78; more is a porting bug.
ALLOWED_DISAGREEMENTS = 2


@pytest.fixture(scope="module")
def scoped() -> TopicScopeDetector:
    from flowx_border.models.registry import ModelUnavailableError

    detector = TopicScopeDetector()
    try:
        detector.warm()
    except ModelUnavailableError as error:
        pytest.skip(f"topic-scope-v2 weights not available: {error}")
    return detector


def as_taxonomy(nodes: list[dict[str, str]], disallowed: str | None = None) -> dict:
    """A fixture row's options as a policy taxonomy, one node disallowed if named."""
    allowed = [
        {"path": n["key"], "description": n["text"]}
        for n in nodes
        if n["key"] != disallowed
    ]
    banned = [
        {"path": n["key"], "description": n["text"]}
        for n in nodes
        if n["key"] == disallowed
    ]
    return {"taxonomy": {"allowed": allowed, "disallowed": banned}}


# ------------------------------------------------------------------- the fixtures


def test_the_fixtures_cover_every_language_and_both_answers() -> None:
    assert {row["language"] for row in ROWS} == set(LANGUAGES)
    per_language = Counter(row["language"] for row in ROWS)
    assert set(per_language.values()) == {3}
    # Positives and negatives both: rows about a node, and rows whose answer is none.
    assert {row["gold"] == "none" for row in ROWS} == {True, False}


def test_the_library_answers_as_the_training_run_did(
    scoped: TopicScopeDetector,
) -> None:
    engine = scoped._typed
    disagree, wrong_by_language = [], Counter()
    for index, row in enumerate(ROWS):
        nodes = [(n["key"], n["text"]) for n in row["nodes"]]
        offered = engine.nodes(f"fixture-{index}", nodes, 1)
        decision = engine.decide(row["text"], offered, 1)
        best = max(range(len(decision.keys)), key=decision.probabilities.__getitem__)
        answer = decision.keys[best]
        if answer != row["run_answer"]:
            disagree.append(
                (row["language"], row["register"], answer, row["run_answer"])
            )
        if answer != row["gold"]:
            wrong_by_language[row["language"]] += 1
    assert len(disagree) <= ALLOWED_DISAGREEMENTS, (
        f"{len(disagree)} of {len(ROWS)} rows differ from the training run: "
        f"{disagree}. The weights are the same, so this is the path from text to the "
        "head's inputs: tokenizer, truncation, packing, the none offset or the "
        "temperature."
    )
    # Not a gate on the model, which the card reports on 11,497 rows. A floor that
    # catches an engine answering none to everything, which would agree with the run
    # wherever the run said none and still be useless.
    right = len(ROWS) - sum(wrong_by_language.values())
    assert right >= 0.75 * len(ROWS), (right, dict(wrong_by_language))


# ------------------------------------------------------------------- the findings


def test_a_disallowed_node_fires_with_a_probability(scoped: TopicScopeDetector) -> None:
    row = next(
        r for r in ROWS if r["register"] == "in_node" and r["run_answer"] == r["gold"]
    )
    cfg = DetectorConfig(
        on_fail="block", threshold=0.5, options=as_taxonomy(row["nodes"], row["gold"])
    )
    findings = scoped.run(row["text"], cfg, Context())
    decided = [f for f in findings if f.action != "log"]
    assert len(decided) == 1
    assert decided[0].label.startswith("off_topic__")
    assert decided[0].action == "block"
    assert 0.5 <= decided[0].score <= 1.0
    assert decided[0].model_id == "flowxai/topic-scope-v2"


def test_a_message_about_no_node_says_none_of_these(scoped: TopicScopeDetector) -> None:
    row = next(
        r
        for r in ROWS
        if r["register"] == "out_of_taxonomy" and r["run_answer"] == "none"
    )
    logged = scoped.run(
        row["text"],
        DetectorConfig(threshold=0.5, options=as_taxonomy(row["nodes"])),
        Context(),
    )
    assert [(f.label, f.action) for f in logged] == [(NONE_LABEL, "log")]

    # An allow-list deployment can make "about none of our topics" the refusal.
    blocked = scoped.run(
        row["text"],
        DetectorConfig(
            threshold=0.5, options={**as_taxonomy(row["nodes"]), "on_none": "block"}
        ),
        Context(),
    )
    assert [(f.label, f.action) for f in blocked] == [(NONE_LABEL, "block")]


def test_on_none_must_be_an_action(scoped: TopicScopeDetector) -> None:
    row = ROWS[0]
    cfg = DetectorConfig(options={**as_taxonomy(row["nodes"]), "on_none": "refuse"})
    with pytest.raises(TopicScopeError, match="not an action"):
        scoped.run(row["text"], cfg, Context())


def test_an_unknown_engine_is_refused_rather_than_defaulted(
    scoped: TopicScopeDetector,
) -> None:
    cfg = DetectorConfig(options={**as_taxonomy(ROWS[0]["nodes"]), "engine": "llm"})
    with pytest.raises(TopicScopeError, match="engine"):
        scoped.run("anything", cfg, Context())


def test_a_large_taxonomy_is_shortlisted_and_says_so(
    scoped: TopicScopeDetector,
) -> None:
    """Above MAX_OPTIONS the nearest nodes are kept, and the record shows it."""
    row = next(
        r for r in ROWS if r["register"] == "in_node" and r["run_answer"] == r["gold"]
    )
    nodes = {n["key"]: n for n in row["nodes"]}
    for other in ROWS:
        for n in other["nodes"]:
            nodes.setdefault(n["key"], n)
    assert len(nodes) > MAX_OPTIONS + 5
    cfg = DetectorConfig(
        on_fail="flag",
        threshold=0.3,
        options=as_taxonomy(list(nodes.values()), row["gold"]),
    )
    findings = scoped.run(row["text"], cfg, Context())
    labels = [f.label for f in findings]
    assert SHORTLIST_LABEL in labels
    assert any(label.startswith("off_topic__") for label in labels), labels


def test_it_attests_without_being_warmed() -> None:
    """`warm` is an optimisation, never a precondition, attestation included."""
    from flowx_border.models.registry import ModelUnavailableError, available

    if not available("topic_scope_v2"):
        pytest.skip("topic-scope-v2 weights not available")
    cold = TopicScopeDetector()
    row = ROWS[0]
    try:
        findings = cold.run(
            row["text"],
            DetectorConfig(threshold=0.0, options=as_taxonomy(row["nodes"])),
            Context(),
        )
    except ModelUnavailableError as error:
        pytest.skip(f"topic-scope-v2 weights not cached: {error}")
    assert findings
    assert {f.model_id for f in findings} == {"flowxai/topic-scope-v2"}
    assert all(f.model_revision and len(f.model_revision) == 40 for f in findings)


def test_the_bi_encoder_is_still_selectable(scoped: TopicScopeDetector) -> None:
    from flowx_border.models.registry import ModelUnavailableError

    row = next(r for r in ROWS if r["register"] == "in_node")
    cfg = DetectorConfig(
        threshold=0.0,
        options={**as_taxonomy(row["nodes"], row["gold"]), "engine": "bi-encoder"},
    )
    try:
        findings = scoped.run(row["text"], cfg, Context())
    except ModelUnavailableError as error:
        pytest.skip(f"topic-scope bi-encoder weights not cached: {error}")
    assert NONE_LABEL not in [f.label for f in findings]
    assert {f.model_id for f in findings} <= {"flowxai/topic-scope"}
