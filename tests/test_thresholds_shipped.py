# SPDX-License-Identifier: Apache-2.0
"""An omitted threshold does not inherit the shipped value, and nothing said so.

`DetectorPolicy.threshold` is `Field(default=0.5)` for every detector in the catalogue.
That default is uniform because the resolver fills it before the policy is hashed, so
two policies meaning the same thing hash the same, and the flat value was never
revisited
against what the detectors actually ship at:

    gibberish 0.37   injection 0.43   nsfw 0.76   bias 0.77
    moderation 0.80  toxicity 0.81    topic_scope 0.85   politeness 0.89

Eight of the ten model-backed detectors, none of them at 0.5. `policies/` is not
packaged
either, `pyproject.toml` ships `src/flowx_border` only, so a caller who installs the
library and writes their own policy has no copy of those numbers and no way to inherit
them.

Reported from outside on 2026-09-15 by a deployment whose policy stated a threshold on
three detectors and omitted it on twenty-seven. They ran `moderation` at 0.5 against
0.80
and `injection` at 0.5 against 0.43 for the life of the document: over-firing on one,
and
under-firing on the only model-backed detector in their configuration that can block.

These tests do not change the default, which is a behaviour question for the owner. They
pin the catalogue against the shipped policy in both directions, so the reference values
`registry.threshold_notes` compares against cannot drift from the file they came from.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from flowx_border import load_policy
from flowx_border.detectors.catalogue import CATALOGUE
from flowx_border.registry import threshold_notes

POLICIES = Path(__file__).resolve().parent.parent / "policies"


def _stated(policy_file: str) -> dict[str, float]:
    """Thresholds the file states, read from the raw YAML rather than the resolved one.

    It has to be the raw document: `_resolve` fills the default in, so a loaded policy
    cannot distinguish a stated 0.5 from an omitted key, which is the whole defect.
    """
    raw = yaml.safe_load((POLICIES / policy_file).read_text(encoding="utf-8"))
    return {
        detector: entry["threshold"]
        for detector, entry in raw["detectors"].items()
        if isinstance(entry, dict) and "threshold" in entry
    }


def test_the_catalogue_carries_what_the_default_policy_states() -> None:
    """Every threshold in `default.yaml` reaches `Spec.shipped_threshold`."""
    for detector, value in sorted(_stated("default.yaml").items()):
        assert CATALOGUE[detector].shipped_threshold == pytest.approx(value), (
            f"{detector}: policies/default.yaml states {value} and the catalogue says "
            f"{CATALOGUE[detector].shipped_threshold}. threshold_notes compares a "
            "caller's policy against the catalogue, so a stale entry there would "
            "report the wrong bar as the shipped one."
        )


def test_the_catalogue_claims_nothing_the_default_policy_does_not_state() -> None:
    """The other direction, and the one that keeps the first from being vacuous.

    A `shipped_threshold` for a detector `default.yaml` says nothing about would be a
    number invented here, and `threshold_notes` would then report a caller as deviating
    from a value no shipped policy uses.
    """
    stated = _stated("default.yaml")
    invented = sorted(
        detector
        for detector, spec in CATALOGUE.items()
        if spec.shipped_threshold is not None and detector not in stated
    )
    assert not invented, (
        f"the catalogue carries a shipped threshold for {', '.join(invented)}, which "
        "policies/default.yaml does not state. Either state it there or drop it here; "
        "a reference value with no shipped policy behind it is a number this project "
        "made up."
    )


def test_the_shipped_default_policy_deviates_from_itself_nowhere() -> None:
    """The fixed point: `default.yaml` is the reference, so it must produce no notes."""
    assert threshold_notes(load_policy(str(POLICIES / "default.yaml"))) == ()


def test_every_bfsi_deviation_is_one_the_file_states_on_purpose() -> None:
    """`bfsi.yaml` is allowed to differ, and every difference has to be deliberate.

    This found a real one on its first run: `bfsi.yaml` enables `politeness`, which
    `default.yaml` leaves off, and stated no threshold for it, so the stricter of the
    two
    shipped policies ran it at 0.5 against the 0.89 chosen for that detector. Every
    other
    deviation in that file carries a comment beside it; that one carried silence.

    So the assertion is not "bfsi matches default", which would be false by design. It
    is
    that a deviation is stated rather than defaulted into.
    """
    stated = _stated("bfsi.yaml")
    policy = load_policy(str(POLICIES / "bfsi.yaml"))
    silent = sorted(
        detector
        for detector, spec in CATALOGUE.items()
        if spec.shipped_threshold is not None
        and policy.enabled_for(detector)
        and detector not in stated
        and policy.for_detector(detector).threshold != spec.shipped_threshold
    )
    assert not silent, (
        f"policies/bfsi.yaml enables {', '.join(silent)} and states no threshold, so "
        "each runs at DetectorPolicy's flat 0.5 rather than at the value chosen "
        "for it. "
        "An omitted threshold is not an inherited one. State the value, whether it "
        "agrees with default.yaml or deliberately does not."
    )


def test_a_policy_that_omits_a_threshold_is_reported_rather_than_corrected() -> None:
    """The reported case, end to end, and the direction that matters most.

    `injection` is the detector the reporting deployment had below stock, and it is the
    one that blocks, so the note says so. Nothing here changes the threshold: the
    library
    still fires at what the policy resolved to, and only the caller can decide whether
    that was what they meant.
    """
    policy = load_policy(
        str(Path(__file__).resolve().parent / "fixtures" / "policies" / "silent.yaml")
    )
    assert policy.for_detector("injection").threshold == pytest.approx(0.5)

    notes = threshold_notes(policy)
    injection = [line for line in notes if line.startswith("injection ")]
    assert injection, f"injection is not reported: {notes}"
    assert "0.43" in injection[0] and "above" in injection[0]
    assert "block" in injection[0], (
        "a detector set to block is the case where a silently lowered bar is "
        "invisible, "
        "so the note has to say the action"
    )
