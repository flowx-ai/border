# SPDX-License-Identifier: Apache-2.0
"""flowx-border: inspects the text crossing into and out of an LLM.

The public API is two scan functions and a policy loader, and that is the whole of it.
Everything else in this package is an implementation detail or an adapter. If a task
appears to need a third public entry point, stop and ask, see CLAUDE.md.

Both scan functions raise NotImplementedError until phase 1 of BUILD_PLAN.md.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from os import PathLike

    from flowx_border.detectors.base import Context
    from flowx_border.types import Decision

__all__ = ["load_policy", "scan_input", "scan_output"]

_PHASE_1 = "is implemented in phase 1 of BUILD_PLAN.md, the policy layer and the engine"


def load_policy(path: str | PathLike[str]) -> Any:  # noqa: ANN401
    """Load, validate and resolve a policy document, and compute its hash.

    The return annotation stays Any until policy.py exists and can name Policy. It is
    the one deliberate hole in the type surface and it closes in phase 1.
    """
    raise NotImplementedError(f"load_policy {_PHASE_1}")


def scan_input(
    text: str,
    policy: Any,  # noqa: ANN401
    ctx: Context | None = None,
) -> Decision:
    """Inspect text on its way to the model."""
    raise NotImplementedError(f"scan_input {_PHASE_1}")


def scan_output(
    text: str,
    policy: Any,  # noqa: ANN401
    ctx: Context | None = None,
) -> Decision:
    """Inspect text on its way back from the model."""
    raise NotImplementedError(f"scan_output {_PHASE_1}")
