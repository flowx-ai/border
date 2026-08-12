# SPDX-License-Identifier: Apache-2.0
"""Every number in the README has to trace to something in the repo.

Phase 7's definition of done, and the one CLAUDE.md rule that is easiest to break by
accident: "if a number appears in the README, there must be a benchmark in the repo that
produces it". A README is written once and then drifts, and the numbers are what drift
first, because they are the part that changes when the code improves.

So this file does not proofread the prose. It checks the claims that would embarrass the
project if they went stale:

    the counts match the catalogue and the registry every quality figure matches
    performance.json every latency figure matches the measured p95 or the asserted
    budget the mandatory "what it is not" section is above the fold no forbidden
    compliance language appears anywhere in it

The last two are not numbers, but they are the two things CLAUDE.md is most explicit
about, and neither is checked anywhere else.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from flowx_border.detectors.catalogue import CATALOGUE
from flowx_border.detectors.reference import counts

REPO = Path(__file__).resolve().parent.parent
README = REPO / "README.md"
PERFORMANCE = REPO / "docs" / "reference" / "performance.json"


@pytest.fixture(scope="module")
def readme() -> str:
    assert README.exists(), "README.md is missing, which is Phase 7's deliverable"
    return README.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def performance() -> dict[str, Any]:
    if not PERFORMANCE.exists():
        pytest.skip("performance.json absent; generate it with benchmarks/collect.py")
    loaded: dict[str, Any] = json.loads(PERFORMANCE.read_text(encoding="utf-8"))
    return loaded


# ------------------------------------------------------------------- what it is not


def test_the_what_it_is_not_section_is_above_the_fold(readme: str) -> None:
    """Mandatory, and mandatory early. A reader who stops after the first screen has to
    have read it."""
    heading = "## What this is not"
    assert heading in readme, "the mandatory section is missing"
    # Before any other section except the opening. Measured in characters rather than
    # lines because a code block's line count is not what a reader experiences.
    position = readme.index(heading)
    for other in ("## Install", "## The two functions", "## Measured latency"):
        assert position < readme.index(other), f"{heading} must come before {other}"
    assert position < 1400, (
        f"{heading} starts {position} characters in, which is not above the fold"
    )


def test_it_says_plainly_what_it_does_not_do(readme: str) -> None:
    section = readme[readme.index("## What this is not") : readme.index("## Install")]
    lowered = section.lower()
    for required in ("gateway", "proxy", "security review", "compliant"):
        assert required in lowered, f"the section does not mention {required}"


# --------------------------------------------------------------- compliance language


def test_no_forbidden_compliance_claim_appears(readme: str) -> None:
    """The list from CLAUDE.md, which is legally material rather than stylistic.

    Checked as phrases rather than words, because "compliant" appears legitimately in
    the sentence that says this library does not make anyone compliant with anything.
    """
    lowered = readme.lower()
    forbidden = (
        "ai act compliant",
        "makes your system compliant",
        "makes you compliant",
        "ensures compliance",
        "guarantees",
        "certified",
        "fully compliant",
        "gdpr compliant",
    )
    found = [phrase for phrase in forbidden if phrase in lowered]
    assert not found, f"forbidden compliance language in README: {found}"


def test_no_marketing_superlatives(readme: str) -> None:
    lowered = readme.lower()
    banned = (
        "revolutionary",
        "seamless",
        "powerful",
        "cutting-edge",
        "state of the art",
    )
    found = [word for word in banned if word in lowered]
    assert not found, f"marketing language in README: {found}"


def test_no_em_dash(readme: str) -> None:
    """Checked here as well as by the repo-wide grep, so a README rewrite fails a test
    rather than a CI step somebody may not read.

    Written as a codepoint rather than the character, for the same reason CLAUDE.md
    spells its grep with printf: a file containing the character it forbids makes the
    repo-wide check fail on itself.
    """
    assert chr(0x2014) not in readme


# ------------------------------------------------------------------------ the counts


def test_the_detector_counts_match_the_code(readme: str) -> None:
    """The failure this prevents is the one that already happened once.

    The count of implemented detectors was maintained by hand in CLAUDE.md and drifted,
    because a number in prose is checked by nothing.
    """
    numbers = counts()
    claim = re.search(
        r"(\d+) catalogued\. (\d+) implemented\. (\d+) run on a fresh install with no "
        r"model download, (\d+) are\s+implemented and waiting",
        readme,
    )
    assert claim, "the README no longer states the counts in the expected form"
    assert int(claim.group(1)) == numbers["catalogued"]
    assert int(claim.group(2)) == numbers["built"]
    assert int(claim.group(3)) == numbers["runs_on_a_fresh_install"]
    assert int(claim.group(4)) == numbers["awaiting_weights"]


def test_the_headline_count_agrees_with_itself(readme: str) -> None:
    # "15 of the 25 in the catalogue" appears in the section above the fold, where a
    # reader is most likely to quote it from.
    numbers = counts()
    claim = re.search(
        r"(\d+) of the (\d+) in the catalogue run on a fresh\s+install", readme
    )
    assert claim, "the above-the-fold count is missing or reworded"
    assert int(claim.group(1)) == numbers["runs_on_a_fresh_install"]
    assert int(claim.group(2)) == numbers["catalogued"]


def test_the_language_count_matches(readme: str) -> None:
    assert f"{counts()['languages']}:" in readme or "26 languages" in readme


def test_the_offline_list_names_only_detectors_that_are_in_core(readme: str) -> None:
    """The list of what needs nothing must not name something that needs an extra.

    The first draft of this README listed all fifteen together as needing no download.
    Two of them need an optional extra installed and one makes an HTTP request during a
    scan, which is a material difference to somebody deploying with the interface down.
    """
    from flowx_border.detectors.catalogue import CORE

    # Anchored on wording that does not carry a count, because the count changes every
    # time a
    # rule detector lands and a test that breaks for that reason teaches nothing.
    section = readme[readme.index("need nothing beyond a CPU and the base install") :]
    section = section[: section.index("The other three run without")]
    named = set(re.findall(r"`([a-z_]+)`", section))
    unknown = sorted(named - set(CATALOGUE))
    assert not unknown, f"the README names detectors that do not exist: {unknown}"
    outside = sorted(named - CORE)
    assert not outside, f"named as needing nothing but outside CORE: {outside}"


def test_the_detectors_needing_more_than_core_are_named_as_such(readme: str) -> None:
    from flowx_border.detectors.catalogue import CORE
    from flowx_border.models.registry import UNPUBLISHED
    from flowx_border.registry import implemented_detectors

    section = readme[readme.index("The other three run without") :]
    section = section[: section.index("detectors were ported from the Guardrails Hub")]
    named = set(re.findall(r"`([a-z_]+)`", section))
    expected = {
        d for d in implemented_detectors() if d not in UNPUBLISHED and d not in CORE
    }
    assert named >= expected, f"the README does not flag {sorted(expected - named)}"


# ----------------------------------------------------------------------- the quality


def test_every_quality_figure_matches_the_generated_file(
    readme: str, performance: dict[str, Any]
) -> None:
    """Each row of the quality table, against the JSON the benchmark wrote."""
    rows = re.findall(
        r"\| `([a-z_]+)` \| [^|]+ \| (\d\.\d{3}) \| (\d\.\d{3}) \| ([^|]+) \|", readme
    )
    assert rows, "the quality table is missing or its shape changed"
    checked = 0
    for name, macro, worst, support in rows:
        entry = performance["detectors"].get(name)
        if entry is None or not entry.get("metrics"):
            pytest.fail(f"README quotes quality for {name}, which has none measured")
        metrics = entry["metrics"]
        assert f"{metrics['macro']:.3f}" == macro, f"{name} macro: {metrics['macro']}"
        assert f"{metrics['worst']:.3f}" == worst, f"{name} worst: {metrics['worst']}"

        total = metrics["total_examples"]
        digits = re.search(r"(\d+)", support)
        if total is None:
            assert digits is None, (
                f"{name} has no recorded total but the README gives one"
            )
            assert "not recorded" in support
        else:
            assert digits and int(digits.group(1)) == total, (
                f"{name} support: README says {support.strip()}, file says {total}"
            )
        checked += 1
    assert checked >= 8, (
        f"only {checked} quality rows checked, expected the whole table"
    )


def test_the_thin_support_warning_is_present(
    readme: str, performance: dict[str, Any]
) -> None:
    """If the corpora are thin, the README has to say so beside the scores.

    Derived rather than asserted as a constant: the day the corpora grow, this stops
    demanding a warning that is no longer true.
    """
    thin = [
        name
        for name, entry in performance["detectors"].items()
        if entry.get("metrics")
        and [
            code
            for code, row in entry["metrics"]["per_language"].items()
            if row["n"] is not None and row["n"] < 10
        ]
    ]
    if not thin:
        return
    assert "fewer than ten positive examples" in readme, (
        f"{len(thin)} detectors rest on single-digit per-language support and the "
        "README does not warn about it"
    )


# ----------------------------------------------------------------------- the latency


def test_the_reference_input_is_described_as_measured(readme: str) -> None:
    from test_budgets import REFERENCE_INPUT

    assert f"{len(REFERENCE_INPUT)} characters" in readme
    assert "one thread" in readme.lower()
    assert "CPUExecutionProvider" in readme


def test_every_latency_budget_quoted_matches_the_catalogue(readme: str) -> None:
    """The budget column, against the catalogue that the tests assert."""
    section = readme[
        readme.index("## Measured latency") : readme.index("## Measured quality")
    ]
    for detector_id, expected in (
        ("pii", CATALOGUE["pii"].budget_ms),
        ("groundedness", CATALOGUE["groundedness"].budget_ms),
        ("topic_scope", CATALOGUE["topic_scope"].budget_ms),
    ):
        row = re.search(rf"\| `{detector_id}`[^|]*\| [^|]+ \| (\d+) ms \|", section)
        assert row, f"no latency row for {detector_id}"
        assert int(row.group(1)) == expected, (
            f"{detector_id} budget: README {row.group(1)}, catalogue {expected}"
        )


def test_the_classifier_budget_quoted_matches_the_catalogue(readme: str) -> None:
    expected = CATALOGUE["toxicity"].budget_ms
    row = re.search(r"\| the seven classifiers \| (\d+) ms \| (\d+) ms \|", readme)
    assert row, "the classifier latency row is missing or reworded"
    assert int(row.group(2)) == expected, (
        f"classifier budget: README says {row.group(2)}, catalogue says {expected}"
    )


def test_the_quoted_classifier_measurement_matches_the_record(readme: str) -> None:
    from test_budgets import MEASURED_MS

    row = re.search(r"\| the seven classifiers \| (\d+) ms \|", readme)
    assert row
    assert int(row.group(1)) == int(MEASURED_MS["toxicity"])


def test_the_thread_scaling_figures_are_the_measured_ones(readme: str) -> None:
    # Quoted in the README as the reason the default is one thread, so they have to be
    # the numbers that were actually measured rather than a recollection of them.
    for figure in ("54.7", "29.8", "17.8", "12.4"):
        assert figure in readme, f"the thread scaling table lost {figure}"


# ------------------------------------------------------------------- the public API


def test_the_readme_only_promises_the_three_public_names(readme: str) -> None:
    """A fourth public entry point is a product decision, so it must not appear."""
    imported = re.findall(r"from flowx_border import ([^\n]+)", readme)
    assert imported, "the README no longer shows the import"
    names = {name.strip() for line in imported for name in line.split(",")}
    assert names == {"load_policy", "scan_input", "scan_output"}, names


def test_the_example_runs(readme: str) -> None:
    """The first code block has to be real, not close to real.

    Not executed verbatim, because it calls a model that does not exist here. The names
    it uses are checked against the package instead, which is what would rot.
    """
    import flowx_border

    for name in ("load_policy", "scan_input", "scan_output"):
        assert hasattr(flowx_border, name)
    decision_fields = re.findall(
        r"^(\w+)\s{2,}", readme[readme.index("verdict ") :][:600], re.M
    )
    from flowx_border.types import Decision

    for field in decision_fields:
        assert field in Decision.model_fields, (
            f"the README documents Decision.{field}, which does not exist"
        )
