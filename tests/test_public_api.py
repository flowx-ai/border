# SPDX-License-Identifier: Apache-2.0
"""The public surface is two scan functions and a policy loader.

This file exists to make surface creep fail a test rather than pass a review.
"""

from __future__ import annotations

import inspect

import pytest

import flowx_border

EXPECTED_API = ["load_policy", "scan_input", "scan_output"]


def test_the_public_api_is_exactly_three_names() -> None:
    assert flowx_border.__all__ == EXPECTED_API


def test_nothing_else_is_re_exported_at_the_top_level() -> None:
    # Core types, the engine and any Guard-shaped wrapper stay internal. A wrapper
    # around the LLM call is explicitly not what this library is.
    for name in ("Decision", "EvidenceRecord", "Finding", "Guard", "engine", "policy"):
        assert not hasattr(flowx_border, name), f"{name} leaked into the public API"


@pytest.mark.parametrize("name", EXPECTED_API)
def test_every_public_function_raises_until_its_phase_lands(name: str) -> None:
    func = getattr(flowx_border, name)
    args = ["policy.yaml"] if name == "load_policy" else ["some text", object()]
    with pytest.raises(NotImplementedError, match="BUILD_PLAN"):
        func(*args)


def test_the_scan_functions_share_one_signature() -> None:
    # An adapter that works for one side must work for the other without a special
    # case, so the two signatures stay identical.
    assert inspect.signature(flowx_border.scan_input) == inspect.signature(
        flowx_border.scan_output
    )


def test_ctx_is_optional_on_both_scan_functions() -> None:
    for func in (flowx_border.scan_input, flowx_border.scan_output):
        assert inspect.signature(func).parameters["ctx"].default is None
