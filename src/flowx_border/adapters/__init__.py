# SPDX-License-Identifier: Apache-2.0
"""Integration adapters.

Deliberately not imported by `flowx_border/__init__.py`. Each adapter imports a
framework
the library does not depend on, so importing the package must not drag LangGraph or
FastAPI in. A caller reaches for the one they need:

    from flowx_border.adapters.fastapi import guard_dependency
    from flowx_border.adapters.langgraph import guard_node
    from flowx_border.adapters.llm_guard_compat import scan_prompt

None of them is a third public entry point in the sense CLAUDE.md restricts: each is a
wrapper over `scan_input` and `scan_output`, holds no logic of its own, and would be
correct to delete. BUILD_PLAN.md puts the ceiling at roughly 120 lines each, on the
theory
that an adapter needing more than that is evidence the core API is wrong.
"""
