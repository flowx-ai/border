# SPDX-License-Identifier: Apache-2.0
"""Per-entity action overrides on `pii`, and why `date` uses one.

One `on_fail` for seven entity types cannot express what the measurement asked for.
`tests/test_ordinary_text_sweep.py` measured a block or a redact on 0.756 of ordinary
rows in 26 languages, and `date` alone accounted for 0.594 of them: times, temperatures
and delivery dates, none of which is personal data on its own.

The shape of the fix is the part worth testing. Dropping `date` from `entities` would
have removed the noise and the evidence together, leaving a record that cannot be
distinguished from one for a text with no dates in it. Lowering the action keeps the
finding and keeps the text.
"""

from __future__ import annotations

import pytest

from flowx_border.detectors.base import DetectorConfig
from flowx_border.detectors.pii import PiiDetector


def config(**options: object) -> DetectorConfig:
    return DetectorConfig(
        enabled=True, threshold=0.5, on_fail="redact", always=False, options=options
    )


@pytest.fixture(scope="module")
def detector() -> PiiDetector:
    return PiiDetector()


def test_no_override_leaves_every_entity_at_the_policy_action(
    detector: PiiDetector,
) -> None:
    assert detector._entity_actions(config()) == {}
    assert detector._entity_actions(config(entity_actions={})) == {}


def test_an_override_is_read_case_insensitively(detector: PiiDetector) -> None:
    """A policy is written by hand and the detector table spells these upper case."""
    assert detector._entity_actions(config(entity_actions={"DATE": "FLAG"})) == {
        "date": "flag"
    }


def test_an_unknown_entity_raises_rather_than_being_ignored(
    detector: PiiDetector,
) -> None:
    """The same refusal `_wanted_entities` makes, for the same reason.

    A policy that wrote `dates: flag` and was ignored would keep redacting every date
    while its author believed otherwise, and nothing in the evidence record would show
    the override had not applied.
    """
    with pytest.raises(ValueError, match="unknown entity type 'dates'"):
        detector._entity_actions(config(entity_actions={"dates": "flag"}))


def test_an_unknown_action_raises(detector: PiiDetector) -> None:
    with pytest.raises(ValueError, match="which is not one of"):
        detector._entity_actions(config(entity_actions={"date": "ignore"}))


def test_a_non_mapping_raises(detector: PiiDetector) -> None:
    """`entity_actions: [date]` is the plausible mistake, and a list has no action in
    it."""
    with pytest.raises(ValueError, match="must be a mapping"):
        detector._entity_actions(config(entity_actions=["date"]))
