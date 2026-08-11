# SPDX-License-Identifier: Apache-2.0
"""Tests for the Guardrails Hub inventory and the document rendered from it.

The inventory's only job is to be complete and to stay in step with the document, so
that is what is asserted. A port table that quietly lost a row would turn into a claim
that a validator was never considered, which is exactly the impression the file exists
to prevent.

The count is pinned at 65 deliberately. If the upstream repository grows a validator,
this test fails and somebody has to decide what to do with it, which is better than an
inventory that silently describes a snapshot nobody can date.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flowx_border.detectors.catalogue import CATALOGUE
from flowx_border.detectors.guardrails_hub import (
    DECLINED,
    PORTED,
    REASONS,
    all_validators,
    gaps,
    render_declined_table,
    render_ported_table,
    render_reasons_table,
)

DOC = (
    Path(__file__).resolve().parent.parent / "docs" / "porting-guardrails-validators.md"
)

#: The validator directories in guardrails-ai/guardrails-hub-monorepo as of 2026-08-11,
#: excluding `.github` and `scripts`, which are not validators.
HUB_COUNT = 65


# ------------------------------------------------------------------- completeness


def test_every_hub_validator_is_either_ported_or_declined() -> None:
    assert len(all_validators()) == HUB_COUNT


def test_no_validator_is_both_ported_and_declined() -> None:
    assert not set(PORTED) & set(DECLINED)


def test_every_port_names_a_detector_that_exists() -> None:
    # A port pointing at a detector id the catalogue does not have would be a claim
    # that something runs when nothing does.
    for name, entry in PORTED.items():
        assert entry.detector in CATALOGUE, f"{name} points at {entry.detector}"


def test_every_decline_uses_a_known_reason_code() -> None:
    for name, entry in DECLINED.items():
        assert entry.reason in REASONS, f"{name} has reason {entry.reason!r}"


def test_every_reason_code_is_used() -> None:
    # An unused code is a row in the rendered table that explains nothing.
    used = {entry.reason for entry in DECLINED.values()}
    assert set(REASONS) == used


def test_every_entry_carries_a_note() -> None:
    for name, entry in list(PORTED.items()) + list(DECLINED.items()):
        assert entry.note.strip(), f"{name} has no explanation"


def test_the_ported_detectors_are_all_represented() -> None:
    assert {entry.detector for entry in PORTED.values()} == {
        "banned_terms",
        "system_prompt_leakage",
        "markup_injection",
        "internal_domains",
        "output_format",
        "sql_injection",
        "url_reachability",
    }


def test_the_gaps_are_the_declines_worth_revisiting() -> None:
    """Pinned, so flipping a gap flag is a deliberate edit with a test behind it.

    Fifteen since 2026-08-11, when the constraints stopped being prohibitions. Most of
    these were declined because a rule forbade them rather than because the check was
    not worth having, so lifting the rules turned them from refusals into a backlog.
    """
    assert len(gaps()) == 12
    assert "llamaguard_7b" in gaps()
    # exclude_sql_predicates and valid_sql left this list on 2026-08-11 by being
    # built: they are `sql_injection`, the first detector outside CORE.
    assert "exclude_sql_predicates" not in gaps()
    # Nothing already answered by a detector is a gap: that would be a request to build
    # a second one.
    assert not [name for name in gaps() if DECLINED[name].reason == "covered"]


def test_every_covered_decline_names_a_detector_that_exists() -> None:
    # A `covered` note pointing at a detector id the catalogue does not have would be a
    # claim that a check runs somewhere when it runs nowhere.
    for name, entry in DECLINED.items():
        if entry.reason != "covered":
            continue
        assert any(f"`{known}`" in entry.note for known in CATALOGUE), (
            f"{name} is declined as covered but names no detector"
        )


# ------------------------------------------------------------------------ the document


def test_the_document_exists() -> None:
    assert DOC.exists(), "docs/porting-guardrails-validators.md is missing"


@pytest.mark.parametrize(
    "render", [render_reasons_table, render_ported_table, render_declined_table]
)
def test_each_rendered_table_appears_verbatim_in_the_document(render: object) -> None:
    """The anti-drift assertion, and the reason the tables are generated at all.

    Regenerate with:
        uv run python -m flowx_border.detectors.guardrails_hub
    """
    table = render()  # type: ignore[operator]
    assert table in DOC.read_text(encoding="utf-8"), (
        "the document no longer contains this table verbatim. Regenerate it rather "
        "than editing the table by hand."
    )


def test_the_document_names_every_validator() -> None:
    text = DOC.read_text(encoding="utf-8")
    for name in all_validators():
        assert f"`{name}`" in text, f"{name} is not named in the document"


def test_the_document_states_the_two_things_the_retrain_still_has_to_settle() -> None:
    """Retraining fixes the licence. It does not fix either of the other two.

    Neither is a reason not to do it, and both are things that go wrong silently if
    nobody writes them down: an unpinned generative detector produces a different
    verdict for the same input, and a 1.6B pass on CPU misses every budget in the table.
    """
    text = DOC.read_text(encoding="utf-8")
    assert "Pin decoding" in text
    assert "Give it a budget it can meet" in text


def test_the_document_frames_the_backlog_as_requirements_rather_than_refusals() -> None:
    # The reason codes double as the `Spec.requires` tags a built version would carry,
    # so the not-ported table is also the backlog. If that link is dropped the table
    # goes back to reading like a list of refusals.
    text = DOC.read_text(encoding="utf-8")
    assert "Spec.requires" in text


# ------------------------------------------------------------------------- packages


def test_only_the_detectors_that_declare_a_requirement_are_outside_core() -> None:
    """Core is the package that runs on a laptop with the interface down.

    One detector is outside it, `sql_injection`, which needs the sqlglot parser. Pinned
    by name so that a second one leaving core is a deliberate edit with a test behind
    it: leaving core changes what a caller has to provide before the detector will run
    at all, and that should never be something a change drifts into.
    """
    from flowx_border.detectors.catalogue import CORE

    assert set(CATALOGUE) - CORE == {"sql_injection", "url_reachability"}
    assert CATALOGUE["sql_injection"].requires == {"dependency"}
    assert CATALOGUE["url_reachability"].requires == {"network"}


def test_a_detector_declaring_a_requirement_is_reported_against_it() -> None:
    from flowx_border.detectors.catalogue import REQUIREMENTS, Spec, requirements_for

    # Built here rather than by mislabelling a real detector, because nothing shipped
    # today needs anything and asserting otherwise would be a false claim in a table.
    hosted = Spec("T2", frozenset({"output"}), 75.0, frozenset({"network", "gpu"}))
    assert hosted.requires == {"network", "gpu"}
    for requirement in hosted.requires:
        assert requirement in REQUIREMENTS

    # An id the catalogue does not carry contributes nothing rather than raising: this
    # reads a policy, and a policy naming an unknown id is the policy loader's error.
    assert requirements_for(["not_a_detector"]) == {}


def _policy(**detectors: object) -> object:
    from flowx_border.policy import DetectorPolicy, Policy

    return Policy(
        policy_id="notes-test",
        version=1,
        fail_mode=dict.fromkeys(("T0", "T1", "T2", "T3"), "open"),
        detectors={
            name: DetectorPolicy(enabled=bool(value))
            for name, value in detectors.items()
        },
    )


def test_the_two_requirement_codes_in_use_are_the_ones_declared() -> None:
    # The vocabulary in the catalogue and the vocabulary in the backlog are the same
    # words on purpose, so "this validator would need network" and "this detector needs
    # network" read as the same statement.
    from flowx_border.detectors.catalogue import REQUIREMENTS

    in_use = {
        requirement for spec in CATALOGUE.values() for requirement in spec.requires
    }
    assert in_use == {"dependency", "network"}
    assert in_use <= set(REQUIREMENTS)


def test_a_core_only_policy_produces_no_deployment_notes() -> None:
    """Silence is the common case and has to stay silent.

    A library that printed a note for every scan would train the caller to ignore the
    one that matters.
    """
    from flowx_border.registry import deployment_notes

    core_only = _policy(sql_injection=False, url_reachability=False)
    assert deployment_notes(core_only) == ()  # type: ignore[arg-type]


def test_a_policy_that_states_nothing_is_told_about_the_non_core_detector() -> None:
    """Defaults enable everything, so the default is that the caller is told.

    This is the direction the silence has to fail in. A policy that says nothing about
    `sql_injection` gets it enabled, and the note is how the caller learns they have
    taken on a parser dependency. The opposite default, silence unless asked, would put
    the discovery in production.
    """
    from flowx_border.registry import deployment_notes

    notes = deployment_notes(_policy())  # type: ignore[arg-type]
    assert len(notes) == 2
    assert any("sql_injection" in note for note in notes)
    assert any("url_reachability" in note for note in notes)


def test_the_shipped_policies_stay_inside_core() -> None:
    from pathlib import Path

    from flowx_border import load_policy
    from flowx_border.registry import deployment_notes

    policies = Path(__file__).resolve().parent.parent / "policies"
    for path in sorted(policies.glob("*.yaml")):
        assert deployment_notes(load_policy(path)) == (), path.name
