# SPDX-License-Identifier: Apache-2.0
"""What the README still has to get right, now that it carries no numbers.

This file used to check nineteen things, because the README used to publish the detector
counts, every quality figure and every latency figure. The rule behind those checks was
that a number in the README must trace to a benchmark in the repo, and they existed
because a README is written once and then drifts, numbers first.

**On 2026-08-17 the README was cut to installation and usage, and fourteen of those
checks went with it.** That is not a loss of coverage, and the reason is worth saying
so nobody restores them out of caution: every figure they guarded is still guarded, in
the file that actually publishes it.

    the detector counts        docs/detectors.md, generated, tests/test_reference.py
    every quality figure       docs/reference/performance.json, test_performance.py
    every latency figure       the same file, plus tests/test_budgets.py
    which detectors are core   docs/detectors.md, generated from CATALOGUE

The README's numbers were duplicates of those, and a duplicate is the copy that goes
stale. What is left is the checks that are about the README rather than about a number,
plus two about links and policies, which is the failure mode a documentation index has.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
README = REPO / "README.md"


@pytest.fixture(scope="module")
def readme() -> str:
    assert README.exists(), "README.md is missing"
    return README.read_text(encoding="utf-8")


# ------------------------------------------------------------------ compliance language


def test_no_forbidden_compliance_claim_appears(readme: str) -> None:
    """The rule that is legally material rather than stylistic.

    This library produces evidence about controls that were applied. It does not make
    anyone compliant with anything, and that difference is the whole reason the evidence
    record exists. Checked here because it is checked nowhere else, and because a
    marketing edit is exactly how it would get broken.
    """
    lowered = readme.lower()
    for phrase in (
        "ai act compliant",
        "gdpr compliant",
        "makes your system compliant",
        "ensures compliance",
        "guarantees compliance",
        "certified",
        "fully compliant",
    ):
        assert phrase not in lowered, f"forbidden compliance claim: {phrase}"


def test_it_still_says_it_makes_nobody_compliant(readme: str) -> None:
    """The disclaimer is kept even in a minimal README, and this is why.

    Cutting the README to usage removed the "what this is not" section, and that was
    right for the rest of it. This sentence stayed, because the README still describes
    an evidence record and signing, and a reader told about audit artifacts and nothing
    about their limits can reasonably infer a claim nobody is making.
    """
    assert "does not make anyone compliant" in readme.lower(), (
        "the README no longer says it makes nobody compliant. It still describes an "
        "evidence record, so the limit has to be stated beside it."
    )


# --------------------------------------------------------------------------- the prose


def test_no_marketing_superlatives(readme: str) -> None:
    lowered = readme.lower()
    for word in (
        "revolutionary",
        "seamless",
        "powerful",
        "cutting-edge",
        "state-of-the-art",
        "world-class",
        "best-in-class",
        "effortless",
    ):
        assert word not in lowered, f"marketing language in the README: {word}"


def test_no_em_dash(readme: str) -> None:
    """The character is built from its code point on purpose.

    Written as a literal first, which put an em-dash in this file and would have failed
    the repository's own style job on the first public CI run. The rule is checked by
    grep across every source file, so a test that spells the character it forbids
    matches itself.
    """
    em_dash = chr(0x2014)
    assert em_dash not in readme, "the README contains an em-dash"


# ----------------------------------------------------------------------------- the API


def test_the_readme_only_promises_the_three_public_names(readme: str) -> None:
    """A fourth public entry point is a product decision, so it must not appear."""
    imported = re.findall(r"from flowx_border import ([^\n]+)", readme)
    assert imported, "the README no longer shows the import"
    names = {name.strip() for line in imported for name in line.split(",")}
    assert names == {"load_policy", "scan_input", "scan_output"}, names


def test_the_documented_decision_fields_exist(readme: str) -> None:
    """The most valuable check here, because this block is what a reader copies.

    Not executed verbatim, since the example calls a model that does not exist in the
    suite, so the names are checked against the package, which is what would rot.
    """
    import flowx_border

    for name in ("load_policy", "scan_input", "scan_output"):
        assert hasattr(flowx_border, name)

    from flowx_border.types import Decision

    fields = re.findall(r"^(\w+)\s{2,}", readme[readme.index("verdict ") :][:600], re.M)
    assert fields, "the README no longer documents the Decision fields"
    for field in fields:
        assert field in Decision.model_fields, (
            f"the README documents Decision.{field}, which does not exist"
        )


# -------------------------------------------------------------- the index, and policies


def test_every_documentation_link_resolves(readme: str) -> None:
    """The new failure mode: the README is largely an index, so a dead link breaks it.

    Relative links only. An external URL is somebody else's uptime rather than this
    test's business, and checking one would put the network in the default suite.
    """
    links = re.findall(r"\]\((?!https?://)([^)#]+)", readme)
    assert links, "the README has no relative links, so the documentation index is gone"
    missing = [target for target in links if not (REPO / target.strip()).exists()]
    assert not missing, f"README links to files that do not exist: {missing}"


def test_the_shipped_policies_the_readme_names_exist(readme: str) -> None:
    """`policies/default.yaml` is in the usage example and has to be loadable.

    Loaded rather than stat-ed: a policy that exists and does not parse satisfies a file
    check and fails the reader on their first line.
    """
    from flowx_border import load_policy

    named = set(re.findall(r"policies/[\w-]+\.yaml", readme))
    assert named, "the usage example no longer names a shipped policy"
    for name in named:
        path = REPO / name
        assert path.exists(), f"the README names {name}, which does not exist"
        load_policy(str(path))
