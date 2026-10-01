# SPDX-License-Identifier: Apache-2.0
"""`topic_scope` against 400 hand-written probes, the check its test split cannot be.

The probes in `fixtures/topic_scope/hand_written_probes.json` were written by hand, not
generated and not drawn from the training corpus: short, plain questions of the kind a
deployment receives, in 10 languages, against three small taxonomies (banking twice,
with keyword-list and with sentence descriptions of the same nodes, insurance and
telecom), each with 3 allowed and 3 disallowed nodes. Every number on the model card
that comes from the training repository comes from synthetic rows written by the same
models that wrote the training set; these are the check from outside that style.

They are why topic-scope-v3 ships with the none offset at -0.5 rather than its fitted
-0.25, and they are what found the engine's known limitation: about 35% of short
plain in-scope questions get "none of these", from v2 and v3 alike. That is a log-level
finding by default and a refusal under `options.on_none`, so an allow-list deployment
should measure it on its own traffic before turning `on_none` into a block.

The floors are what topic-scope-v3 scored at -0.5 on 2026-10-01 (in 130/200, dis 91/120,
out 80/80), less a tolerance for a CPU or onnxruntime that rounds differently. A fall
below them is a regression; a rise is welcome and should raise them.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

os.environ.setdefault("HF_HUB_OFFLINE", "1")

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.topic_scope import NONE_LABEL, TopicScopeDetector

pytestmark = pytest.mark.slow

PROBES = Path(__file__).parent / "fixtures" / "topic_scope" / "hand_written_probes.json"
FIXTURE: dict[str, Any] = json.loads(PROBES.read_text(encoding="utf-8"))

#: Passes per kind, topic-scope-v3 at none offset -0.5, measured 2026-10-01.
MEASURED = {"in": 130, "dis": 91, "out": 80}
#: Probes per kind a different machine may round the other way. Three of 400.
TOLERANCE = 3


@pytest.fixture(scope="module")
def results() -> list[dict[str, Any]]:
    from flowx_border.models.registry import ModelUnavailableError

    detector = TopicScopeDetector()
    try:
        detector.warm()
    except ModelUnavailableError as error:
        pytest.skip(f"topic_scope typed weights not available: {error}")
    out = []
    for probe in FIXTURE["probes"]:
        cfg = DetectorConfig(
            on_fail="flag",
            threshold=FIXTURE["threshold"],
            options={"taxonomy": FIXTURE["taxonomies"][probe["taxonomy"]]},
        )
        findings = detector.run(probe["text"], cfg, Context())
        decided = [f.label for f in findings if f.action != "log"]
        said_none = any(f.label == NONE_LABEL for f in findings)
        if probe["kind"] == "in":
            ok = not decided and not said_none
        elif probe["kind"] == "dis":
            ok = decided == ["off_topic__" + probe["expected"].replace("/", "__")]
        else:
            ok = not decided
        out.append({**probe, "ok": ok, "decided": decided, "said_none": said_none})
    return out


def test_the_fixture_is_the_set_the_floors_were_measured_on() -> None:
    probes = FIXTURE["probes"]
    assert len(probes) == 400
    assert len({p["text"] for p in probes}) == 300
    assert {p["language"] for p in probes} == {
        "en",
        "ro",
        "de",
        "fr",
        "es",
        "it",
        "pl",
        "nl",
        "pt",
        "tr",
    }
    assert FIXTURE["measured_2026_10_01"]["topic-scope-v3, none offset -0.5"] == {
        kind: [MEASURED[kind], total]
        for kind, total in (("in", 200), ("dis", 120), ("out", 80))
    }


@pytest.mark.parametrize("kind", ["in", "dis", "out"])
def test_each_kind_holds_its_floor(results: list[dict[str, Any]], kind: str) -> None:
    rows = [r for r in results if r["kind"] == kind]
    passed = sum(r["ok"] for r in rows)
    misses = [
        f"{r['language']} {r['taxonomy']}: {r['text']}" for r in rows if not r["ok"]
    ]
    assert passed >= MEASURED[kind] - TOLERANCE, (passed, len(rows), misses[:20])


def test_an_in_scope_miss_is_none_of_these_and_never_a_refusal(
    results: list[dict[str, Any]],
) -> None:
    """The limitation's shape: in-scope misses are "none", not a disallowed node firing.

    So the default policy, which logs "none", refuses none of them; only a deployment
    that sets `options.on_none` to block does.
    """
    fired = [r for r in results if r["kind"] == "in" and r["decided"]]
    assert len(fired) <= TOLERANCE, [(r["text"], r["decided"]) for r in fired]
