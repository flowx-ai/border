# SPDX-License-Identifier: Apache-2.0
"""Tests for the generated detector reference.

This file exists because of a mistake it would have caught. The count of implemented
detectors was maintained by hand in CLAUDE.md, incremented by hand each time one landed,
and drifted to 13 when the answer was 12. Nothing noticed, because a number in prose is
not checked by anything.

So the number is computed now, and the two places that state it are asserted against the
computation rather than against each other. The same applies to the table in
docs/detectors.md, which is what anyone describing this library externally is meant to
read.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from flowx_border.detectors.catalogue import CATALOGUE
from flowx_border.detectors.reference import (
    NOT_BUILT,
    SUMMARIES,
    counts,
    render_counts,
    render_requirements,
    render_table,
    rows,
)

DOC = Path(__file__).resolve().parent.parent / "docs" / "detectors.md"
CLAUDE_MD = Path(__file__).resolve().parent.parent / "CLAUDE.md"


# --------------------------------------------------------------------- completeness


def test_every_catalogued_detector_has_a_summary() -> None:
    # A blank row in a table people quote from is worse than no table.
    missing = sorted(set(CATALOGUE) - set(SUMMARIES))
    assert not missing, f"no summary for: {', '.join(missing)}"


def test_no_summary_describes_a_detector_that_does_not_exist() -> None:
    assert not sorted(set(SUMMARIES) - set(CATALOGUE))


def test_every_not_built_entry_names_a_real_detector() -> None:
    assert set(NOT_BUILT) <= set(CATALOGUE)


def test_every_row_has_a_status_and_it_is_derived() -> None:
    """Status comes from the registry rather than from a list somebody maintains.

    The failure being prevented is a page that says a check runs when it does not, and
    the way that happens is a hand-kept list nobody updates when a detector stops
    loading.

    Derived from `implemented_detectors` rather than `loaded_detectors`, because this
    document is checked in and has to read the same on every machine. Against the loaded
    set, the assertion held only where the classifier weights were absent and broke as
    soon as they were present, which made it a test about the developer's disk.
    """
    from flowx_border.registry import implemented_detectors

    implemented = set(implemented_detectors())
    for row in rows():
        assert row.status
        assert (row.status == "built") == (row.detector_id in implemented), (
            row.detector_id
        )


def test_a_detector_that_is_not_built_says_why() -> None:
    for row in rows():
        if row.status == "built":
            continue
        assert row.status != "not built", (
            f"{row.detector_id} is not built and NOT_BUILT does not say why"
        )


# ------------------------------------------------------------------------- the counts


def test_the_counts_add_up() -> None:
    numbers = counts()
    assert numbers["built"] + numbers["not_built"] == numbers["catalogued"]
    assert numbers["core"] + numbers["outside_core"] == numbers["catalogued"]
    assert numbers["catalogued"] == len(CATALOGUE)


def test_claude_md_states_the_computed_number_of_real_detectors() -> None:
    """The assertion that would have caught the drift.

    CLAUDE.md is read before every task and is where the figure gets quoted from. It
    said 13 of 21 when the answer was 12 of 21, because the number was incremented by
    hand each time a detector landed and once it was incremented twice.
    """
    numbers = counts()
    match = re.search(r"v1 is (\d+) of (\d+) detectors real", CLAUDE_MD.read_text())
    assert match, "CLAUDE.md no longer states the count in the expected form"
    # "Real" is the number that runs for somebody who installs the library, which is not
    # the number implemented: seven classifiers are written and wired but wait on
    # weights that are not published, so they check nothing on a fresh install.
    # Asserting against `built` would let CLAUDE.md claim 22 working detectors while 7
    # of them are inert, which is the claim this project refuses to make anywhere else.
    assert int(match.group(1)) == numbers["runs_on_a_fresh_install"]
    assert int(match.group(2)) == numbers["catalogued"]


# --------------------------------------------------------------------- the document


def test_the_document_exists() -> None:
    assert DOC.exists(), "docs/detectors.md is missing"


@pytest.mark.parametrize("render", [render_counts, render_table, render_requirements])
def test_each_rendered_block_appears_verbatim_in_the_document(render: object) -> None:
    """Regenerate with:

    uv run python -m flowx_border.detectors.reference
    """
    block = render()  # type: ignore[operator]
    assert block in DOC.read_text(encoding="utf-8"), (
        "docs/detectors.md no longer matches the code. Regenerate it rather than "
        "editing the table by hand."
    )


def test_the_document_names_every_detector() -> None:
    text = DOC.read_text(encoding="utf-8")
    for detector_id in CATALOGUE:
        assert f"`{detector_id}`" in text, detector_id


def test_the_document_carries_the_language_caveat() -> None:
    """The claim most likely to be overstated somewhere public.

    Fixtures cover 26. The PII model was trained on nine. Both are true and only one of
    them is what "supports 26 languages" sounds like.
    """
    text = DOC.read_text(encoding="utf-8")
    assert "trained on nine" in text
    assert "do not say the model covers 26" in text


def test_the_document_carries_the_compliance_language_rules() -> None:
    # The obligations sit with the provider or deployer of a system, not with a library,
    # so this is materially misleading rather than merely overenthusiastic.
    text = DOC.read_text(encoding="utf-8")
    for forbidden in ("AI Act compliant", "guarantees", "certified"):
        assert forbidden in text, f"{forbidden} is not listed as a thing not to say"
    # Shortened so the assertion survives the line wrap in the document.
    assert "does not make anyone compliant" in text


def test_the_document_contains_no_forbidden_claim_of_its_own() -> None:
    """The document lists phrases not to use, so it necessarily contains them.

    Every occurrence has to be inside the section that says not to use them. Checked by
    position rather than by absence, because the naive assertion is impossible here and
    a page copied from the wrong half of this file is the exact failure being avoided.
    """
    text = DOC.read_text(encoding="utf-8")
    boundary = text.index("## Things that must not be said")
    for forbidden in ("AI Act compliant", "makes your system compliant", "certified"):
        assert forbidden not in text[:boundary], (
            f"{forbidden!r} appears before the section that forbids it"
        )
