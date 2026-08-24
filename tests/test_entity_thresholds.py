# SPDX-License-Identifier: Apache-2.0
"""Per-entity score bars on `pii`, and the one this file used to argue `person` needed.

`person` was the one entity type with no shape to check, before `location` existed.
Every other type has one: a checksum for CARD and IBAN, a format for EMAIL and PHONE, a
length and a scheme for NATIONAL_ID. So `entity_shapes.py` could reject a malformed IBAN
and had nothing to say about a capitalised word, and an unfamiliar capitalised token
mid-sentence landed in `person` because there was nowhere else for it to go.

Measured over 234 ordinary rows in 26 languages on 2026-08-19: 43 of 51 damaging `pii`
findings were `person`, and the spans were place names, `Regensburg` and `Valletta`
among them. A score bar at 0.90 papered over it, removing 30 of the 43 at no measured
cost to real names.

**That bar is gone as of 2026-08-20, when the model gained `location` as an eighth
type.** The problem was never `person`'s to solve: a place had nowhere correct to go
in a 7-type schema, and giving it one made the bar's job obsolete rather than smaller.
Every `person` finding across the same 234 rows is now checked by hand and is a genuine
person, zero toponyms. `national_id` and `phone` keep their bars in the shipped policy,
because both address a genuinely bimodal score that `location` does not touch, and this
file still exercises the `entity_thresholds` mechanism generically through them.

The trap the old bar had to avoid, and `location` avoids the same way: place names are
common surnames, so a fix making toponym shape predict "not an entity" would trade a
visible over-redaction for an invisible hole, which `entity_shapes.py` refuses to do.
Tagging the two apart, rather than scoring them apart, has the same property: nothing
here drops a span, it names it.
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
    """Unwarmed. The end-to-end tests below warm it through `warmed` and skip if they
    cannot, because CI runs the whole suite with `HF_HUB_OFFLINE` and an empty cache."""
    return PiiDetector()


@pytest.fixture(scope="module")
def warmed(detector: PiiDetector) -> PiiDetector:
    """A warmed detector, or a skip naming what is missing.

    CI runs `pytest -q` with no marker filter and no model cache, so a slow marker does
    not keep a model-backed test out of it. The first version of this file called
    `warm()` in a test and turned a missing artifact into a red build, not a skip.
    """
    from flowx_border.models.registry import ModelUnavailableError

    try:
        detector.warm()
    except ModelUnavailableError as error:
        pytest.skip(f"piiguard weights not cached: {error}")
    return detector


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
def test_a_place_name_is_tagged_location_not_dropped_from_person(
    warmed: PiiDetector,
) -> None:
    """The bar this option existed for is gone, and this is why.

    Until 2026-08-20 the model had no LOCATION type, so a place name had nowhere correct
    to go and landed in `person`. `entity_thresholds: {person: 0.90}` in the shipped
    policy compensated by dropping the low end of that distribution. The retrain
    that added LOCATION made the bar's job obsolete rather than smaller: a place is
    now tagged as what it is, architecturally, not filtered by confidence.
    """
    from flowx_border.detectors.base import Context

    detector = warmed
    text = "The service calls at Vilshofen before continuing to the terminus."
    ctx = Context()

    findings = detector.run(text, config(), ctx)
    assert any(f.label == "location" for f in findings), (
        f"the place was not tagged location at all: "
        f"{[(f.label, round(f.score, 3)) for f in findings]}"
    )
    assert not any(f.label == "person" for f in findings), (
        "a toponym is still landing in person, which is the failure the bar used to "
        f"paper over: {[(f.label, round(f.score, 3)) for f in findings]}"
    )


@pytest.mark.slow
def test_a_person_named_after_a_place_is_found_as_a_person(warmed: PiiDetector) -> None:
    """The hole a stoplist of toponyms would have punched, now closed by tagging.

    Place names are common surnames. Before LOCATION existed, the model separated the
    two by context and a score bar kept that separation from being undone by
    over-redaction elsewhere. Now the separation is the label itself: a place-shaped
    surname used as a person's name is tagged `person`, and no bar is needed to protect
    that, because there is no longer a competing `person` reading of an actual place to
    filter out.
    """
    from flowx_border.detectors.base import Context

    detector = warmed
    ctx = Context()

    person = "The parcel was signed for by Frau Regensburg on Tuesday morning."
    found = [f for f in detector.run(person, config(), ctx) if f.label == "person"]
    assert found, "a person whose surname is a place name was not found"
