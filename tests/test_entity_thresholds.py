# SPDX-License-Identifier: Apache-2.0
"""Per-entity score bars on `pii`, and why `person` needs one.

`person` is the one entity type with no shape to check. Every other has one: a checksum
for CARD and IBAN, a format for EMAIL and PHONE, a length and a scheme for NATIONAL_ID.
So `entity_shapes.py` can reject a malformed IBAN and has nothing to say about a
capitalised word, and an unfamiliar capitalised token mid-sentence lands in `person`.

Measured over 234 ordinary rows in 26 languages: 43 of 51 damaging `pii` findings were
`person`, and the spans were place names. An ablation inside fixed frames separated the
variables and neither is what the failures looked like:

    Berlin, Paris, Siemens, Volkswagen    never tagged, familiar from pretraining
    Regensburg, Valletta, Plattling       tagged 0.51 to 0.97
    Grelmshof, an invented token          tagged 0.89 to 0.97
    any of them sentence-initial          not tagged, capitalisation is orthography

So it is unfamiliarity rather than knowledge of place names, and a bar on confidence
reaches it where a stoplist of toponyms could not.

The trap this must avoid is in `test_a_person_named_after_a_place_is_still_found`. Place
names are common surnames, so a fix making toponym shape predict "not an entity" would
trade a visible over-redaction for an invisible hole, which `entity_shapes.py` already
refuses to do. A bar on score does not have that failure mode, and the test pins it.
"""

from __future__ import annotations

import pytest

from flowx_border.detectors.base import DetectorConfig
from flowx_border.detectors.pii import PiiDetector


def config(threshold: float = 0.5, **options: object) -> DetectorConfig:
    return DetectorConfig(
        enabled=True,
        threshold=threshold,
        on_fail="redact",
        always=False,
        options=options,
    )


@pytest.fixture(scope="module")
def detector() -> PiiDetector:
    return PiiDetector()


def test_no_bar_is_the_default(detector: PiiDetector) -> None:
    assert detector._entity_thresholds(config()) == {}
    assert detector._entity_thresholds(config(entity_thresholds={})) == {}


def test_a_bar_is_read_and_normalised(detector: PiiDetector) -> None:
    got = detector._entity_thresholds(config(entity_thresholds={"PERSON": "0.9"}))
    assert got == {"person": 0.9}


@pytest.mark.parametrize(
    "bad,why",
    [
        ({"persson": 0.9}, "a misspelled type would silently keep the detector's bar"),
        ({"person": "high"}, "not a number"),
        ({"person": 1.5}, "outside 0.0 to 1.0"),
        ({"person": -0.1}, "outside 0.0 to 1.0"),
    ],
)
def test_a_bar_that_would_not_apply_raises(
    detector: PiiDetector, bad: dict[str, object], why: str
) -> None:
    """Silence here is the dangerous outcome: the entity stays at the detector's own bar
    and nothing in the record shows that the policy's intent was dropped."""
    with pytest.raises(ValueError):
        detector._entity_thresholds(config(entity_thresholds=bad))


def test_entity_thresholds_must_be_a_mapping(detector: PiiDetector) -> None:
    with pytest.raises(ValueError, match="mapping"):
        detector._entity_thresholds(config(entity_thresholds=[0.9]))


# ------------------------------------------------------------------ end to end


@pytest.mark.slow
def test_a_place_name_below_the_bar_is_dropped_and_recorded(
    detector: PiiDetector,
) -> None:
    """The point of the option, and the record still shows what the bar did."""
    from flowx_border.detectors.base import Context

    text = "The service calls at Vilshofen before continuing to the terminus."
    ctx = Context()
    detector.warm()

    without = detector.run(text, config(), ctx)
    assert any(f.label == "person" and f.action == "redact" for f in without), (
        "the case this option exists for no longer reproduces: "
        f"{[(f.label, round(f.score, 3)) for f in without]}"
    )

    with_bar = detector.run(text, config(entity_thresholds={"person": 0.90}), ctx)
    assert not any(f.label == "person" for f in with_bar), (
        f"the bar did not drop it: {[(f.label, round(f.score, 3)) for f in with_bar]}"
    )
    assert any("below_entity_threshold" in f.label for f in with_bar), (
        "the bar dropped a span and recorded nothing, which leaves a record "
        "indistinguishable from a text that had no name-shaped token in it"
    )
    assert all(
        f.action == "log" for f in with_bar if "below_entity_threshold" in f.label
    ), "a bar's own record must never carry the policy's action"


@pytest.mark.slow
def test_a_person_named_after_a_place_is_still_found(detector: PiiDetector) -> None:
    """The hole a stoplist of toponyms would have punched, and the bar does not.

    Place names are common surnames. The model already separates the two by context, so
    raising a score bar keeps that: a person in a person frame scores far above 0.90
    while the same token as a place scores below it.
    """
    from flowx_border.detectors.base import Context

    ctx = Context()
    detector.warm()
    cfg = config(entity_thresholds={"person": 0.90})

    person = "The parcel was signed for by Frau Regensburg on Tuesday morning."
    found = [f for f in detector.run(person, cfg, ctx) if f.label == "person"]
    assert found, "a person whose surname is a place name was not found"
    assert max(f.score for f in found) >= 0.90, (
        "a real person scored under the bar, which is the hole this test exists to "
        f"prevent: {[(f.label, round(f.score, 3)) for f in found]}"
    )

    place = "The parcel was delivered to Regensburg on Tuesday morning."
    kept = [f for f in detector.run(place, cfg, ctx) if f.label == "person"]
    assert not kept, f"the place survived the bar: {[round(f.score, 3) for f in kept]}"
