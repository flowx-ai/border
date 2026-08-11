# SPDX-License-Identifier: Apache-2.0
"""flowx-border: inspects the text crossing into and out of an LLM.

The public API is two scan functions and a policy loader, and that is the whole of it.
Everything else in this package is an implementation detail or an adapter. If a task
appears to need a third public entry point, stop and ask, see CLAUDE.md.

Both scan functions raise NotImplementedError until phase 1 of BUILD_PLAN.md.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from os import PathLike

    from flowx_border.detectors.base import Context
    from flowx_border.policy import Policy
    from flowx_border.types import Decision

__all__ = ["load_policy", "scan_input", "scan_output"]


def load_policy(path: str | PathLike[str]) -> Policy:
    """Load, validate and resolve a policy document, and compute its hash.

    Raises PolicyError for anything wrong with the file, including an unknown detector
    id. It never falls back to a default: scanning under a policy the caller did not
    write is worse than refusing to start.
    """
    from flowx_border.policy import load_policy as _load

    return _load(path)


def _scan(text: str, side: str, policy: Policy, ctx: Context | None) -> Decision:
    """The body both scan functions share.

    `assert_satisfiable` runs first, and it is the reason this indirection
        exists. With a detector missing, `run_scan` would return `allow` for text
        nobody checked, and the caller would archive an evidence record for a scan
        that enforced nothing. So a policy asking a missing detector to block or
        redact raises here instead. Detectors asked only to flag or log are allowed
        through, because there the gap shows up in the record rather than being
        hidden by it.

        Measured at 0.004 ms against the shipped default policy, against a 1 ms T0
        budget: cheap enough to run per scan rather than cache and risk going stale.
    """
    from flowx_border.engine import run_scan
    from flowx_border.registry import assert_satisfiable, loaded_detectors

    assert_satisfiable(policy, side)
    return run_scan(text, side, policy, ctx, loaded_detectors())


def scan_input(text: str, policy: Policy, ctx: Context | None = None) -> Decision:
    """Inspect text on its way to the model.

    Raises DetectorUnavailableError when the policy expects a detector this
    install does not have to enforce something. It does not silently pass the text.
    """
    return _scan(text, "input", policy, ctx)


def scan_output(text: str, policy: Policy, ctx: Context | None = None) -> Decision:
    """Inspect text on its way back from the model.

    Raises DetectorUnavailableError when the policy expects a detector this
    install does not have to enforce something. It does not silently pass the text.
    """
    return _scan(text, "output", policy, ctx)
