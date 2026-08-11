# SPDX-License-Identifier: Apache-2.0
"""A LangGraph node that scans the message state.

`guard_node(policy, side)` returns a callable to drop into a graph. It reads the last
message, scans it, writes back the possibly-redacted text, and puts the Decision on the
state under `border` so a later node or a human reviewer can read the evidence record.

**A block routes, it does not raise.** An exception inside a graph node becomes a
traceback
in someone's request handler and takes the whole turn down. Routing to a named terminal
node keeps the refusal inside the graph's own control flow, which is where a product
decides what to say to the user. The node name is configurable because only the caller
knows what their graph calls that state.

LangGraph is not imported. The node is a plain callable over a mapping, which is all
LangGraph requires, and that keeps the framework out of the dependency set.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from flowx_border.detectors.base import Context
    from flowx_border.policy import Policy

#: Where the Decision lands on the state. Namespaced so it cannot collide with a graph's
#: own keys.
STATE_KEY = "border"


def guard_node(
    policy: Policy,
    side: str = "input",
    *,
    messages_key: str = "messages",
    blocked_node: str = "blocked",
    ctx: Context | None = None,
) -> Callable[[Mapping[str, Any]], dict[str, Any]]:
    """Build a graph node that scans the most recent message.

    Returns a partial state update, which is what LangGraph expects: the message list
    is
    only rewritten when redaction actually changed the text, so a clean scan adds the
    evidence record and touches nothing else.
    """
    from flowx_border import scan_input, scan_output

    scan = scan_input if side == "input" else scan_output

    def node(state: Mapping[str, Any]) -> dict[str, Any]:
        messages = list(state.get(messages_key) or [])
        if not messages:
            return {}

        last = messages[-1]
        text = (
            last.get("content")
            if isinstance(last, Mapping)
            else getattr(last, "content", "")
        )
        if not isinstance(text, str) or not text:
            return {}

        decision = scan(text, policy, ctx)
        update: dict[str, Any] = {
            STATE_KEY: {
                "verdict": decision.verdict,
                "findings": [f.model_dump() for f in decision.findings],
                "evidence": decision.evidence.model_dump(),
                "elapsed_ms": decision.elapsed_ms,
            }
        }

        if decision.verdict == "block":
            # A routing hint rather than an exception. The graph decides what a refusal
            # looks like; this node only says that one is required.
            update["next"] = blocked_node
            return update

        if decision.text != text:
            replaced = dict(last) if isinstance(last, Mapping) else last
            if isinstance(replaced, dict):
                replaced["content"] = decision.text
            else:
                replaced = {
                    "role": getattr(last, "role", "user"),
                    "content": decision.text,
                }
            update[messages_key] = [*messages[:-1], replaced]

        return update

    return node
