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


def test_the_four_ported_detectors_are_all_represented() -> None:
    assert {entry.detector for entry in PORTED.values()} == {
        "banned_terms",
        "system_prompt_leakage",
        "markup_injection",
        "internal_domains",
    }


def test_the_gaps_are_the_declines_worth_revisiting() -> None:
    # Pinned so that flipping a gap flag is a deliberate edit with a test behind it,
    # rather than something that drifts while the follow-up review is queued.
    assert gaps() == ("exclude_sql_predicates", "llamaguard_7b", "shieldgemma_2b")


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
    # The honest part of that section. Retraining fixes the licence, and leaves both
    # the constraint 4 problem and the CPU budget problem exactly where they were.
    text = DOC.read_text(encoding="utf-8")
    assert "Constraint 4 forbids an LLM call inside a detector" in text
    assert "does not meet a CPU budget" in text
