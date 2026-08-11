# SPDX-License-Identifier: Apache-2.0
"""FastAPI integration, offered as a dependency and as middleware.

Both forms exist because they suit different applications, and picking one for you would
be wrong in half the cases.

`guard_dependency` is the one to reach for. It scans a field you name, and because it is
a
dependency it composes with everything FastAPI already does: it runs after
validation, it
can be applied per route, and the Decision arrives as a normal parameter, so the handler
can decide what to do with a redaction.

`GuardMiddleware` is for retrofitting an application whose handlers you would rather not
touch. It intercepts a JSON path on the request and on the response. It is the blunter
tool: middleware sees bytes and has to parse them, it cannot know which routes carry
user
text, and it applies to all of them until you narrow `paths`.

**A block returns 422 rather than raising.** A refusal is a normal outcome of a guard,
not
a server fault, and a 5xx would page somebody. 422 says the request was understood and
rejected on content, which is what happened. The record id goes in the body so a support
conversation can start from the audit trail rather than from a screenshot.

FastAPI **is** imported at module scope here, and that is deliberate.
`adapters/__init__.py`
imports no submodule, so `import flowx_border` never reaches this file and the library
keeps
FastAPI out of its dependency set. Importing it lazily inside the factory looked tidier
and
was actually broken: with `from __future__ import annotations` every annotation is a
string, FastAPI resolves a dependency's signature with `get_type_hints`, and a
`Request` that only
exists as a local name cannot be resolved. It silently degraded to treating `request` as
a
query parameter, so every call returned 422 with `{"loc": ["query", "request"]}`.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

if TYPE_CHECKING:
    from flowx_border.policy import Policy
    from flowx_border.types import Decision

#  What a blocked request answers with. Not 400: the request was well formed. Not 5xx:
# the
#  server did not fail. 422 is the status FastAPI already uses for content it will not
# act
#: on.
BLOCKED_STATUS = 422


def _blocked_body(decision: Decision) -> dict[str, Any]:
    """The response body for a refusal.

    Carries the record id and the finding summary, and deliberately not the text or the
    spans. A 4xx body is the most likely thing to end up in a log aggregator, a browser
    console or a support ticket, so it gets the same no-raw-text treatment as the
    evidence
    record itself.
    """
    return {
        "detail": "blocked by content policy",
        "record_id": decision.evidence.record_id,
        "policy_id": decision.evidence.policy_id,
        "findings": [
            {"detector": f.detector_id, "label": f.label} for f in decision.findings
        ],
    }


def guard_dependency(
    policy: Policy,
    *,
    field: str = "prompt",
    side: str = "input",
) -> Callable[..., Any]:
    """A FastAPI dependency that scans one field of the JSON body.

    Returns the Decision, so the handler receives the possibly-redacted text as
    `decision.text` and can still see what was found. Raises HTTPException(422) on a
    block,
    which FastAPI turns into a normal response.
    """
    from flowx_border import scan_input, scan_output

    scan = scan_input if side == "input" else scan_output

    async def dependency(request: Request) -> Decision | None:
        try:
            body = await request.json()
        except (json.JSONDecodeError, ValueError):
            # Not JSON, so there is no named field to scan. Letting it through is
            # correct:
            # this dependency guards a field, and a request without that field is the
            # route's problem to reject, not this one's.
            return None

        text = body.get(field) if isinstance(body, dict) else None
        if not isinstance(text, str) or not text:
            return None

        decision = scan(text, policy)
        if decision.verdict == "block":
            raise HTTPException(
                status_code=BLOCKED_STATUS, detail=_blocked_body(decision)
            )
        return decision

    return dependency


def guard_middleware(
    policy: Policy,
    *,
    request_field: str = "prompt",
    response_field: str = "completion",
    paths: tuple[str, ...] = (),
) -> Callable[..., Any]:
    """An ASGI middleware factory scanning a request field and a response field.

    `paths` narrows which routes are touched, and defaulting it to empty means every
    route,
    which is the behaviour someone reaching for middleware is asking for. Narrow it as
    soon
    as you know which routes carry user text: a health check costs a model pass.
    """
    from flowx_border import scan_input, scan_output

    class GuardMiddleware(BaseHTTPMiddleware):
        async def dispatch(
            self, request: Request, call_next: RequestResponseEndpoint
        ) -> Response:
            if paths and not any(str(request.url.path).startswith(p) for p in paths):
                return await call_next(request)

            raw = await request.body()
            if raw:
                try:
                    body = json.loads(raw)
                except (json.JSONDecodeError, ValueError):
                    body = None
                if isinstance(body, dict) and isinstance(body.get(request_field), str):
                    decision = scan_input(body[request_field], policy)
                    if decision.verdict == "block":
                        return JSONResponse(
                            status_code=BLOCKED_STATUS, content=_blocked_body(decision)
                        )

            response = await call_next(request)

            # The response side needs the assembled body, which means buffering the
            # stream. Stated rather than hidden: this makes a streaming response
            # non-streaming, and it is the main reason to prefer the dependency form
            # for an endpoint that streams tokens.
            #
            # Both response shapes are handled. BaseHTTPMiddleware normally hands back
            # a streaming response, but a middleware further down the stack may have
            # buffered it into a plain one already, and assuming body_iterator exists
            # would fail on exactly that stack.
            streaming = getattr(response, "body_iterator", None)
            if streaming is not None:
                payload = b"".join([chunk async for chunk in streaming])
            else:
                payload = bytes(getattr(response, "body", b""))
            try:
                body = json.loads(payload)
            except (json.JSONDecodeError, ValueError):
                # Not JSON, so there is no field to scan. Passed through byte for byte
                # rather than dropped: middleware that eats a non-JSON response because
                # it
                # could not parse it would break every file download in the application.
                return _passthrough(response, payload)

            if isinstance(body, dict) and isinstance(body.get(response_field), str):
                decision = scan_output(body[response_field], policy)
                if decision.verdict == "block":
                    return JSONResponse(
                        status_code=BLOCKED_STATUS, content=_blocked_body(decision)
                    )
                body[response_field] = decision.text
                return JSONResponse(status_code=response.status_code, content=body)

            return _passthrough(response, payload)

    return GuardMiddleware


def _passthrough(response: Response, payload: bytes) -> Response:
    """Return a buffered response unchanged, preserving status and headers."""
    headers = dict(response.headers)
    headers.pop("content-length", None)
    return Response(
        content=payload,
        status_code=response.status_code,
        headers=headers,
        media_type=response.media_type,
    )
