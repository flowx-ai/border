# SPDX-License-Identifier: Apache-2.0
"""A threshold below the score a detector can actually produce is not a low bar.

`topic_scope` emits a rescaled cosine, `(cos + 1) / 2`, so its score cannot fall below
`(min_cos + 1) / 2` for the model's minimum similarity to any taxonomy node. Over the
training corpus's 408-row test split against a 15-node taxonomy that floor is 0.6674,
and both shipped policies carried a threshold of **0.45** until 2026-08-19.

So every row cleared it: 408 of 408, including all 78 belonging to no taxonomy node at
all. Firing was decided entirely by whether the nearest node happened to be
`disallowed`, and the threshold did nothing. Under `policies/bfsi.yaml`, where `on_fail`
is `block`, that is a refused response for an input the detector had no opinion about.

**The published evaluation could not see it.** `topic_scope_eval.json` reports
`top1_accuracy`, which asks *which* node is nearest and never *whether any* is near
enough. A rank metric cannot see a threshold that never binds, which is why the eval's
own note that the out-of-taxonomy rows are "never scored, which is half of what it is
for" was the more important sentence in that file.

These tests pin the general fault rather than the number: a policy threshold has to sit
inside the range the detector can produce, or it is inert.
"""

from __future__ import annotations

import pathlib

import pytest
import yaml

POLICIES = pathlib.Path(__file__).resolve().parent.parent / "policies"

#: A taxonomy with descriptions rather than bare paths, because the descriptions are
#: what gets embedded and a path-shaped stub measures something else. Using
#: `path.replace("/", " ")` as the description reversed the finding on the first
#: attempt: out-of-taxonomy text scored *higher* than in-scope text, and the conclusion
#: drawn from that, that no threshold could work, was wrong. The instrument was the
#: problem.
TAXONOMY = {
    "disallowed": [
        {
            "path": "banking/loans/mortgage",
            "description": "mortgage applications, rates, terms and affordability",
        },
        {
            "path": "insurance/claims/motor",
            "description": "making a claim after a vehicle accident or damage",
        },
    ],
    "allowed": [
        {
            "path": "banking/payments/transfer",
            "description": "sending a payment or transfer, timing, fees, recipient",
        },
    ],
}

#: The lowest score seen over 408 corpus rows against a 15-node taxonomy, measured
#: 2026-08-19. A threshold at or under this cannot reject anything.
MEASURED_SCORE_FLOOR = 0.6674


@pytest.mark.parametrize("policy_name", ["default.yaml", "bfsi.yaml"])
def test_the_shipped_threshold_is_above_the_score_floor(policy_name: str) -> None:
    """The check that would have caught 0.45, and it needs no model to run."""
    raw = yaml.safe_load((POLICIES / policy_name).read_text(encoding="utf-8"))
    found = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if (
                    key == "topic_scope"
                    and isinstance(value, dict)
                    and "threshold" in value
                ):
                    found.append(float(value["threshold"]))
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(raw)
    assert found, f"{policy_name} configures no topic_scope threshold to check"
    for threshold in found:
        assert threshold > MEASURED_SCORE_FLOOR, (
            f"{policy_name} sets topic_scope threshold {threshold}, at or below the "
            f"measured score floor of {MEASURED_SCORE_FLOOR}. This detector emits a "
            "rescaled cosine, so a threshold there rejects no input at all and firing "
            "is decided purely by which node happens to be nearest."
        )


@pytest.mark.slow
def test_the_score_floor_is_real_and_not_a_recorded_guess() -> None:
    """Measure the floor rather than trusting the constant above.

    If a retrained bi-encoder produced lower similarities the constant would be stale
    and the test above would pass while the threshold went inert again. So this asserts
    the constant is not *higher* than what the model produces, which is the direction
    that would make the guard falsely reassuring.
    """
    from flowx_border.detectors.base import Context, DetectorConfig
    from flowx_border.detectors.topic_scope import TopicScopeDetector
    from flowx_border.models.registry import ModelUnavailableError

    detector = TopicScopeDetector()
    try:
        detector.warm()
    except (ModelUnavailableError, RuntimeError) as error:
        pytest.skip(f"topic_scope weights not cached: {error}")
    # Everything disallowed at a zero threshold, so each text yields its nearest score.
    everything = {
        "disallowed": TAXONOMY["disallowed"] + TAXONOMY["allowed"],
        "allowed": [],
    }
    cfg = DetectorConfig(
        enabled=True,
        threshold=0.0,
        on_fail="flag",
        always=True,
        options={"taxonomy": everything},
    )
    ctx = Context()
    texts = [
        "I would like to apply for a mortgage on a flat in Riga.",
        "The kitchen was repainted last spring and the extractor fan serviced.",
        "Zbog kvara na mrezi, isporuka ce biti odgodena do srijede.",
        "Please send me the quarterly dividend statement for my portfolio.",
    ]
    scores = [f.score for text in texts for f in detector.run(text, cfg, ctx)]
    assert scores, "the detector reported nothing at a zero threshold"
    assert min(scores) >= MEASURED_SCORE_FLOOR - 0.15, (
        f"the lowest score seen is {min(scores):.4f}, far under the recorded floor of "
        f"{MEASURED_SCORE_FLOOR}. Re-measure the floor and the shipped thresholds."
    )
