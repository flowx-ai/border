# SPDX-License-Identifier: Apache-2.0
"""The held-out groundedness probes, as a gate rather than as a report.

42 source-and-candidate pairs written by hand on 2026-08-17, in
`training/data/groundedness_probes.csv`. Six sources that each state a condition,
crossed with seven candidate shapes.

**Why this file exists rather than another eval table.** Five groundedness candidates
have been trained and none adopted. The fifth was trained on a `scope_conflict` register
aimed at the shape the others failed, scored 0.9303 on that register's own test split,
and scores 0 of 6 on hand-written examples of the same shape. A test split drawn from
the same generator as the training data cannot tell you a register generalised. So "did
this model learn to compare a claim against a source" cannot be answered by anything the
generator produced, and this is the only groundedness evaluation in either repository
that no generator wrote.

**The gold labels were corrected on 2026-08-17 and the ranking reversed.** The sheet
labelled `drop_qualifier` and `widen_scope` `unsupported`; the corpus labels that shape
`contradicted`, 1,652 rows of each and no `unsupported` at all, and the corpus is right.
Twelve of 42 rows were wrong, in exactly the shapes the newest candidate was built for.

So `scope` did not score 0.310 and come last. It scores 0.548 exact and 0.690 binary and
comes first, with 5 of 6 on both shapes it was trained for against 0 of 6 for every
candidate trained without them. The register worked. See
`training/docs/groundedness-held-out-probes.md`.

**Two metrics, because the detector does not act on three classes.** `REPORTABLE` is
`("unsupported", "contradicted")`, so both mean not grounded and a caller sees the same
action. Binary is what decides behaviour; exact is the harder question. Chance is 0.500
and 0.333.

Nothing passes as an adoption test and nothing is meant to: 0.690 binary is one call in
three wrong. This is a floor that stops one specific failure, a candidate judged only by
an evaluation drawn from its own generator.

**Read `training/docs/groundedness-held-out-probes.md` before changing a number here.**
The per-shape floors are the point: an overall accuracy can be reached by being good at
numeric conflicts and useless at dropped qualifiers, which is what `pairs-v2` does at 6
of 6 and 0 of 6.
"""

from __future__ import annotations

import csv
import os
from pathlib import Path

import pytest

os.environ.setdefault("HF_HUB_OFFLINE", "1")

from flowx_border.models.registry import ModelUnavailableError

pytestmark = pytest.mark.slow

PROBES = (
    Path(__file__).resolve().parent.parent.parent
    / "training"
    / "data"
    / "groundedness_probes.csv"
)

#: Better than chance on three classes. A floor this low is not a target, it is the
#: point below which a model is not doing the task at all, and one candidate is under.
MIN_ACCURACY = 0.45

#: The two shapes that carry the detector's purpose: a candidate that quotes the source
#: and drops the condition, and one taking a narrow permission and claiming it broadly.
#: Neither changes a number and neither negates anything, so a model cannot reach them
#: with the cues the corpus taught. Three of five score 0 of 6 on both, and the two that
#: do not are the two trained on a scope_conflict register.
MIN_PER_SHAPE = {"drop_qualifier": 3, "widen_scope": 3}

#: The binary floor, on the reading the detector's action actually uses. Set below the
#: leading candidate's 0.690 rather than at it, so the gate is a floor and not a
#: reproduction of one measurement.
MIN_BINARY_ACCURACY = 0.65

#: Labels that both mean "not grounded", so a caller sees the same action for either.
UNGROUNDED = frozenset({"unsupported", "contradicted"})


def load_probes() -> list[dict[str, str]]:
    if not PROBES.exists():
        return []
    with PROBES.open(encoding="utf-8-sig") as handle:
        return [
            row
            for row in csv.DictReader(handle)
            if (row.get("candidate") or "").strip()
        ]


@pytest.fixture(scope="module")
def scored() -> dict[str, object]:
    """Every probe judged by whichever groundedness weights this install resolves."""
    probes = load_probes()
    if len(probes) < 20:
        pytest.skip(
            f"only {len(probes)} probes available at {PROBES}. They live in the "
            "training "
            "repository, which a library-only clone does not have."
        )

    from flowx_border.detectors.groundedness import GroundednessDetector

    detector = GroundednessDetector()
    try:
        detector.warm()
    except ModelUnavailableError as error:
        pytest.skip(f"groundedness ships unavailable in this version: {error}")

    per_shape: dict[str, list[int]] = {}
    binary_correct = 0
    wrong: list[str] = []
    for row in probes:
        judged = detector.judge(row["source"], row["candidate"].strip(), 1)
        got = max(judged, key=lambda label: judged[label])
        shape = row["shape"]
        bucket = per_shape.setdefault(shape, [0, 0])
        bucket[1] += 1
        if got == row["label"]:
            bucket[0] += 1
        else:
            wrong.append(f"{row['id']}: expected {row['label']}, got {got}")
        if (got in UNGROUNDED) == (row["label"] in UNGROUNDED):
            binary_correct += 1
    correct = sum(v[0] for v in per_shape.values())
    return {
        "correct": correct,
        "total": len(probes),
        "accuracy": correct / len(probes),
        "binary_accuracy": binary_correct / len(probes),
        "per_shape": per_shape,
        "wrong": wrong,
    }


def test_the_model_beats_chance_on_the_hand_written_probes(
    scored: dict[str, object],
) -> None:
    """The weakest possible bar, and it exists because a candidate came in under it.

    `groundedness-scope` scores 0.310 against 0.333 chance. A model below chance on
    held-out probes is not a model that needs tuning.
    """
    accuracy = scored["accuracy"]
    assert isinstance(accuracy, float)
    report = "\n".join(f"  {line}" for line in list(scored["wrong"])[:12])  # type: ignore[arg-type]
    assert accuracy >= MIN_ACCURACY, (
        f"{scored['correct']}/{scored['total']} = {accuracy:.3f} on the hand-written "
        f"probes, below the {MIN_ACCURACY} floor. Chance is 0.333.\n{report}"
    )


@pytest.mark.parametrize("shape", sorted(MIN_PER_SHAPE))
def test_the_shape_the_detector_exists_for(
    scored: dict[str, object], shape: str
) -> None:
    """Per shape, because an overall figure hides the one that matters.

    `pairs-v2` scores 6 of 6 on numeric conflicts and 0 of 6 here. A single accuracy
    number calls that a middling model; it is a model that cannot do the job at all.
    """
    per_shape = scored["per_shape"]
    assert isinstance(per_shape, dict)
    if shape not in per_shape:
        pytest.skip(f"no {shape} probes in the sheet")
    correct, total = per_shape[shape]
    assert correct >= MIN_PER_SHAPE[shape], (
        f"{shape}: {correct} of {total}, below the floor of {MIN_PER_SHAPE[shape]}. "
        "This is a candidate quoting the source and dropping its condition, with no "
        "changed "
        "number and no negation to lean on."
    )


def test_the_probe_set_still_covers_every_shape() -> None:
    """A sheet that lost a column would make the gate above pass by asking less.

    The failing shapes are the ones most likely to be quietly dropped, since they are
    the ones that keep failing.
    """
    probes = load_probes()
    if not probes:
        pytest.skip(f"probe sheet absent at {PROBES}")
    shapes = {row["shape"] for row in probes}
    assert shapes >= set(MIN_PER_SHAPE), (
        f"the probe sheet lost {sorted(set(MIN_PER_SHAPE) - shapes)}, which "
        "are the shapes the per-shape floors are about."
    )
    assert len(probes) >= 40, f"only {len(probes)} probes; the set was 42"


def test_the_grounded_or_not_call_beats_chance(scored: dict[str, object]) -> None:
    """The reading the detector's action depends on, which is the one that ships.

    A caller configures one action for `unsupported` and `contradicted`, so telling them
    apart is a refinement and telling grounded from not is the job. Kept separate from
    the exact figure because the two disagree about which candidate leads: `fp16` is
    0.333 exact and 0.667 binary.
    """
    binary = scored["binary_accuracy"]
    assert isinstance(binary, float)
    assert binary >= MIN_BINARY_ACCURACY, (
        f"grounded-or-not accuracy {binary:.3f} on the hand-written probes, below the "
        f"{MIN_BINARY_ACCURACY} floor. Chance on this reading is 0.500."
    )
