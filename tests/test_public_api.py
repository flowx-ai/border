# SPDX-License-Identifier: Apache-2.0
"""The public surface is two scan functions and a policy loader.

This file exists to make surface creep fail a test rather than pass a review.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

import flowx_border
from flowx_border.detectors.catalogue import CATALOGUE

EXPECTED_API = ["load_policy", "scan_input", "scan_output"]

POLICIES = Path(__file__).resolve().parent.parent / "policies"


def test_the_public_api_is_exactly_three_names() -> None:
    assert flowx_border.__all__ == EXPECTED_API


def test_nothing_else_is_re_exported_at_the_top_level() -> None:
    # Core types and any Guard-shaped wrapper stay internal. A wrapper around the LLM
    # call is explicitly not what this library is.
    #
    # Submodules are not on this list on purpose. `flowx_border.policy` becomes an
    # attribute of the package the moment anything imports it, which is how Python works
    # and not surface creep: `import *` still yields only __all__, which the test below
    # checks. What must never appear is a type or a class.
    for name in (
        "Decision",
        "EvidenceRecord",
        "Finding",
        "Guard",
        "Scanner",
        "run_scan",
    ):
        assert not hasattr(flowx_border, name), f"{name} leaked into the public API"


def test_a_star_import_brings_in_exactly_the_three_names() -> None:
    namespace: dict[str, object] = {}
    # exec is the thing under test here: it is the only way to observe what a star
    # import actually brings in.
    exec("from flowx_border import *", namespace)  # noqa: S102
    assert sorted(n for n in namespace if not n.startswith("__")) == EXPECTED_API


def test_a_scan_refuses_rather_than_pretending_when_a_detector_is_missing() -> None:
    # The failure this guards: with nothing loaded, a scan would return allow, produce
    # an evidence record, and check nothing. That is worse than an exception, because it
    # is indistinguishable from a clean pass. The shipped default policy asks `secrets`
    # to block, so until Phase 2 lands this is what both functions do.
    from flowx_border.registry import DetectorUnavailableError, loaded_detectors

    policy = flowx_border.load_policy(POLICIES / "default.yaml")
    if "secrets" in loaded_detectors():
        pytest.skip("secrets is loaded, so the default policy is satisfiable")

    for func in (flowx_border.scan_input, flowx_border.scan_output):
        with pytest.raises(DetectorUnavailableError, match="pass as if checked"):
            func("some text", policy)


def test_a_report_only_policy_scans_without_raising(tmp_path: Path) -> None:
    # The other side of the same rule. Nothing enforces, so a missing detector degrades
    # to a gap the record shows rather than a silent pass, and so the scan is allowed to
    # run.
    body = "policy_id: report-only\nversion: 1\ndetectors:\n"
    body += "".join(f"  {name}:\n    on_fail: log\n" for name in CATALOGUE)
    path = tmp_path / "report_only.yaml"
    path.write_text(body, encoding="utf-8")

    policy = flowx_border.load_policy(path)
    decision = flowx_border.scan_input("some text", policy)
    assert decision.verdict == "allow"
    assert decision.evidence.policy_hash == policy.hash


def test_load_policy_refuses_a_missing_file() -> None:
    from flowx_border.policy import PolicyError

    with pytest.raises(PolicyError, match="no policy file"):
        flowx_border.load_policy("does-not-exist.yaml")


def test_the_scan_functions_share_one_signature() -> None:
    # An adapter that works for one side must work for the other without a special case,
    # so the two signatures stay identical.
    assert inspect.signature(flowx_border.scan_input) == inspect.signature(
        flowx_border.scan_output
    )


def test_ctx_is_optional_on_both_scan_functions() -> None:
    for func in (flowx_border.scan_input, flowx_border.scan_output):
        assert inspect.signature(func).parameters["ctx"].default is None
