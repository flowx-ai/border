# SPDX-License-Identifier: Apache-2.0
"""Does a personal detail survive a scan, in every entity type and every locale?

`tests/test_ordinary_text_sweep.py` measures the cost of the detector firing when it
should not. This measures the opposite direction, and nothing measured it end to end
until 2026-08-19, when the gap turned out to be holding a disclosure.

`entity_shapes.is_possible` required four digits for a `NATIONAL_ID`, on the stated
grounds that every scheme in the 26 carries them. An Azerbaijani identifier is seven
alphanumerics and generates with as few as zero. A rejected shape is *dropped*, so the
model found the identifier, tagged it `national_id` correctly, and the caller got it
back with `pii_shape_rejected_national_id` recorded beside it: **52 of 272 held-out
Azerbaijani identifiers survived verbatim.**

**The measurement that existed could not see it.** `heldout_ner_eval` reports token
coverage, which asks whether every gold token is covered by *some* predicted span. These
spans were predicted, so they counted as covered, and were dropped a layer later.
Coverage in the tagger is not survival through the library, and only the second is what
a caller gets. So this test asks the caller's question directly: after `scan_output`, is
the value still there?

It is deliberately not a per-detector test. It goes through `scan_output` with a shipped
policy, so the shape gate, the checksum overrule, the per-entity bars, the redaction and
the span snapping are all in the path, which is where the bug was.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from flowx_border import load_policy, scan_output
from flowx_border.detectors.multilingual import LANGUAGES

FIXTURE = (
    pathlib.Path(__file__).resolve().parent / "fixtures/pii/entities_by_locale.json"
)
POLICIES = pathlib.Path(__file__).resolve().parent.parent / "policies"

#: The frame each value is placed in, and both halves of it are load-bearing.
#:
#: The value sits mid-sentence rather than first, because a sentence-initial capital is
#: orthography and the tagger reads it as such: measured 2026-08-19, `Regensburg` scores
#: 0.68 mid-sentence and nothing at all in first position. A leak test puts the value
#: where the detector is weakest, not where it is strongest.
#:
#: The frame also carries an AI disclosure, and it has to. Without one,
#: `policies/bfsi.yaml` blocks at T0 on `disclosure_missing`, the engine short-circuits
#: with `tiers_run == ["T0"]`, and `pii` never runs at all. The first version of this
#: test did that and reported 26 of 26 PERSON values surviving under bfsi, which was
#: neither a leak nor a pass: it was a test exercising nothing and saying something.
#: `test_pii_actually_ran` below is what stops that recurring.
FRAME = (
    "Automated response. Please update the record: the value on file is {} "
    "and needs checking."
)

ENTITIES = ("PERSON", "EMAIL", "PHONE", "NATIONAL_ID", "IBAN", "CARD")


def entities() -> dict[str, dict[str, str]]:
    return dict(json.loads(FIXTURE.read_text(encoding="utf-8")))


def test_the_fixture_covers_every_supported_locale() -> None:
    """A leak test skipping a locale would be a leak test agreeing with itself."""
    got = set(entities())
    assert got == set(LANGUAGES), (
        f"missing {sorted(set(LANGUAGES) - got)}, extra {sorted(got - set(LANGUAGES))}"
    )


@pytest.mark.parametrize("entity", ENTITIES)
def test_the_fixture_has_a_value_for_every_type_in_every_locale(entity: str) -> None:
    blank = [code for code, row in entities().items() if not row.get(entity)]
    assert not blank, f"{entity} is missing for {blank}"


@pytest.mark.slow
@pytest.mark.parametrize("policy_name", ["default.yaml", "bfsi.yaml"])
def test_pii_actually_ran(policy_name: str) -> None:
    """The guard that makes the test below mean something.

    A T0 block short-circuits the engine, so a frame that trips one produces a scan in
    which `pii` never ran, and every assertion about what `pii` did then passes or fails
    for the wrong reason. This asserts the detector was reached before anything is
    concluded about what it found.
    """
    policy = load_policy(str(POLICIES / policy_name))
    decision = scan_output(FRAME.format(entities()["en"]["PERSON"]), policy)
    assert "T1" in decision.tiers_run, (
        f"{policy_name} did not reach T1, so pii never ran: verdict={decision.verdict} "
        f"tiers={decision.tiers_run}, findings="
        f"{[(f.detector_id, f.label, f.action) for f in decision.findings]}"
    )
    assert any(f.detector_id.startswith("pii") for f in decision.findings), (
        f"{policy_name} reached T1 and pii reported nothing on a text containing a name"
    )


@pytest.mark.slow
@pytest.mark.parametrize("policy_name", ["default.yaml", "bfsi.yaml"])
@pytest.mark.parametrize("entity", ENTITIES)
def test_no_entity_survives_a_scan_in_any_locale(policy_name: str, entity: str) -> None:
    """The caller's question: after the scan, is the value still in the text?

    Parametrised by entity type rather than asserted once over everything, so a failure
    names the type. Run against both shipped policies because they differ in the ways
    that matter here: `bfsi.yaml` takes a lower threshold and no per-entity bars.
    """
    policy = load_policy(str(POLICIES / policy_name))
    survived = []
    for code, row in sorted(entities().items()):
        value = row[entity]
        decision = scan_output(FRAME.format(value), policy)
        # A blocked response is never delivered, so it cannot leak. Counted separately
        # rather than ignored, because a policy that blocked everything would otherwise
        # look like a policy that leaked nothing.
        if decision.verdict == "block":
            continue
        # Whitespace-insensitive: a redaction that removed the value but kept its
        # separators is still a redaction, and one that kept a digit run split across
        # spaces is still a leak.
        if "".join(value.split()) in "".join(decision.text.split()):
            survived.append((code, value, decision.verdict))
    assert not survived, (
        f"{entity} survived {len(survived)} of 26 scans under {policy_name}:\n"
        + "\n".join(f"    [{c}] {v!r} verdict={d}" for c, v, d in survived)
    )


@pytest.mark.slow
def test_a_national_id_with_almost_no_digits_survives_nothing() -> None:
    """The specific shape that leaked, pinned separately from the sweep above.

    Azerbaijan and Italy are the two locales whose identifiers can carry fewer than four
    digits, so they are the two the old digit floor dropped. Named here so that a future
    change to the floor fails on the case rather than on an aggregate.
    """
    policy = load_policy(str(POLICIES / "default.yaml"))
    for code in ("az", "it"):
        value = entities()[code]["NATIONAL_ID"]
        out = scan_output(FRAME.format(value), policy).text
        assert "".join(value.split()) not in "".join(out.split()), (
            f"[{code}] national identifier {value!r} reached the caller, which is what "
            "the four-digit shape floor did to 216 of 240 Azerbaijani identifiers"
        )
