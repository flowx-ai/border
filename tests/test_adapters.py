# SPDX-License-Identifier: Apache-2.0
"""Integration tests for the three adapters, each running a real scan through it.

The property that matters most is in the compat shim: an unsupported scanner must
raise.
A security shim that silently does nothing is worse than one that fails, because the
caller
keeps believing a check is happening. So that has its own tests, and so does the promise
that the migration doc names every scanner the shim knows about.

FastAPI and Starlette are dev-only. The tests that need them skip rather than fail when
they are absent, because they are not runtime dependencies of the library and the
runtime set is kept short.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("HF_HUB_OFFLINE", "1")

from flowx_border.adapters.llm_guard_compat import (
    SUPPORTED,
    UNSUPPORTED,
    UnsupportedScannerError,
    decision_for,
    scan_output,
    scan_prompt,
)
from flowx_border.detectors.catalogue import ALWAYS_ON, CATALOGUE
from flowx_border.policy import DetectorPolicy, Policy

# `secrets` and `disclosure` are the two detectors that need no weights, so an adapter
# test
# can exercise a real end-to-end scan without the model being cached.
RULES_ONLY = ["Secrets"]


# ------------------------------------------------------------------- the compat shim


def test_an_unsupported_scanner_raises_rather_than_passing() -> None:
    """The whole reason this file exists.

    **This test's example has now been wrong twice, and the pattern is the useful
    part.** It was BanCode until code_present landed on 2026-08-12. Then Language,
    chosen with a comment saying it was "declined on grounds that will not change: every
    detector here works in 26 languages rather than gating on which one a text is in".
    That reasoning was wrong within four days: language_id landed on 2026-08-16 for
    exactly the gap the comment said did not exist, and gating is a real thing a caller
    wants.

    So the example is Sentiment now, and no claim is made about it being permanent. A
    scanner is unsupported until somebody builds it, and predicting which ones nobody
    will build is not a thing this file is good at.
    """
    with pytest.raises(UnsupportedScannerError, match="Sentiment"):
        scan_prompt("hello", ["Sentiment"])


def test_the_error_says_why_the_scanner_is_unsupported() -> None:
    # "not supported" is not actionable. Naming the reason is.
    with pytest.raises(UnsupportedScannerError, match="politeness is the nearest"):
        scan_prompt("hello", ["Sentiment"])


def test_an_unknown_scanner_name_also_raises() -> None:
    with pytest.raises(UnsupportedScannerError, match="not a known llm-guard scanner"):
        scan_prompt("hello", ["TotallyMadeUp"])


def test_every_unsupported_scanner_raises_and_none_of_them_no_ops() -> None:
    for name in UNSUPPORTED:
        with pytest.raises(UnsupportedScannerError):
            scan_prompt("hello", [name])


def test_no_scanner_is_in_both_tables() -> None:
    assert not set(SUPPORTED) & set(UNSUPPORTED)


def test_every_supported_scanner_maps_to_a_real_detector() -> None:
    # A mapping onto an id that is not in the catalogue would raise at scan time with a
    # policy error, which is a confusing way to learn about a typo in this table.
    for name, detector in SUPPORTED.items():
        assert detector in CATALOGUE, f"{name} maps to unknown detector {detector}"


def test_scan_prompt_returns_the_llm_guard_tuple_shape() -> None:
    sanitised, valid, scores = scan_prompt("what are your opening hours?", RULES_ONLY)
    assert isinstance(sanitised, str)
    assert set(valid) == {"secrets"}
    assert set(scores) == {"secrets"}
    assert valid["secrets"] is True
    assert scores["secrets"] == 0.0


def test_a_finding_makes_the_scanner_invalid_in_the_llm_guard_sense() -> None:
    _, valid, scores = scan_prompt("my key is AKIAIOSFODNN7EXAMPLE", RULES_ONLY)
    assert valid["secrets"] is False
    assert scores["secrets"] == 1.0


def test_scan_output_passes_the_prompt_as_context() -> None:
    """The prompt is not ignored, which is the point of output_leakage.

    llm-guard's scan_output took the prompt and used it for little. Here it becomes
    Context.sources, which is what lets output_leakage tell a leak from the assistant
    repeating back what the user typed.
    """
    _, valid, _ = scan_output(
        "my email is a@b.co", "Noted, I have recorded a@b.co.", ["Deanonymize"]
    )
    # Without the model cached this cannot assert on findings, but it must not crash and
    # must report the detector the caller asked for.
    assert "output_leakage" in valid


def test_decision_for_returns_the_real_object() -> None:
    # So the tuple is a stepping stone rather than a ceiling: the evidence record is the
    # reason to use this library and llm-guard's shape has nowhere to put it.
    decision = decision_for("hello there", "input", RULES_ONLY)
    assert decision.evidence.record_id
    assert decision.evidence.policy_id == "llm-guard-compat"


def test_t0_runs_even_though_the_caller_did_not_ask_for_it() -> None:
    # T0 cannot be disabled. It reports rather than enforces here, so a migration does
    # not start blocking traffic llm-guard was allowing.
    decision = decision_for("my key is AKIAIOSFODNN7EXAMPLE", "input", ["Toxicity"])
    substantive = [
        f.detector_id for f in decision.findings if f.label != "detector_error"
    ]
    assert substantive == ["secrets"]
    assert decision.verdict == "flag"

    # `detector_error` findings are allowed above and are not incidental. The caller
    # asked for Toxicity, whose weights are not cached on a fresh checkout, and
    # fail_mode open records that as a finding at `log` rather than passing quietly.
    # Asserting the exact list failed on a fresh clone and passed on a machine with the
    # cache, which is the least useful way for a test to be wrong: it made the library
    # doing the right thing look like a regression.
    errors = [f for f in decision.findings if f.label == "detector_error"]
    for finding in errors:
        assert finding.action == "log"


def test_the_compat_policy_disables_what_was_not_requested() -> None:
    from flowx_border.adapters.llm_guard_compat import _policy_for

    policy = _policy_for(["pii"])
    assert policy.enabled_for("pii") is True
    assert policy.enabled_for("toxicity") is False
    # T0 regardless.
    assert policy.enabled_for("secrets") is True


# ------------------------------------------------------------------ the migration doc


def test_the_migration_doc_names_every_scanner() -> None:
    """Supported and unsupported alike.

    The doc is generated from the two tables, so this is really asserting that nobody
    has
    since hand-edited it into disagreeing with the code.
    """
    from pathlib import Path

    doc = (
        Path(__file__).resolve().parent.parent / "docs" / "migrating-from-llm-guard.md"
    )
    assert doc.exists(), "docs/migrating-from-llm-guard.md is missing"
    text = doc.read_text(encoding="utf-8")
    for name in list(SUPPORTED) + list(UNSUPPORTED):
        assert f"`{name}`" in text, f"{name} is not named in the migration doc"


def test_the_migration_doc_names_the_detectors_llm_guard_had_no_equivalent_for() -> (
    None
):
    from pathlib import Path

    doc = (
        Path(__file__).resolve().parent.parent / "docs" / "migrating-from-llm-guard.md"
    )
    text = doc.read_text(encoding="utf-8")
    for detector in set(CATALOGUE) - set(SUPPORTED.values()):
        assert f"`{detector}`" in text


# ---------------------------------------------------------------------- langgraph


def a_policy() -> Policy:
    return Policy(
        policy_id="adapter-test",
        version=1,
        fail_mode=dict.fromkeys(("T0", "T1", "T2", "T3"), "open"),
        detectors={
            # ALWAYS_ON rather than a literal pair: T0 cannot be disabled, and naming
            # the T0 detectors here means this helper breaks every time one is added.
            # It did, when `invisible_text` landed.
            name: DetectorPolicy(
                enabled=name in ALWAYS_ON or name in ("secrets", "disclosure"),
                on_fail="redact",
            )
            for name in CATALOGUE
        },
    )


def test_the_langgraph_node_scans_the_last_message() -> None:
    from flowx_border.adapters.langgraph import STATE_KEY, guard_node

    node = guard_node(a_policy(), "input")
    update = node({"messages": [{"role": "user", "content": "what are your hours?"}]})
    assert update[STATE_KEY]["verdict"] == "allow"
    assert update[STATE_KEY]["evidence"]["record_id"]


def test_the_langgraph_node_rewrites_a_redacted_message() -> None:
    from flowx_border.adapters.langgraph import guard_node

    node = guard_node(a_policy(), "input")
    update = node(
        {"messages": [{"role": "user", "content": "key AKIAIOSFODNN7EXAMPLE here"}]}
    )
    assert "AKIA" not in update["messages"][-1]["content"]
    assert "[AWS_ACCESS_KEY_ID]" in update["messages"][-1]["content"]


def test_the_langgraph_node_routes_on_block_rather_than_raising() -> None:
    """An exception inside a graph node takes the whole turn down.

    Routing keeps the refusal inside the graph's control flow, which is where a product
    decides what to tell the user.
    """
    from flowx_border.adapters.langgraph import guard_node
    from flowx_border.policy import DetectorPolicy, Policy

    blocking = Policy(
        policy_id="blocking",
        version=1,
        fail_mode=dict.fromkeys(("T0", "T1", "T2", "T3"), "open"),
        detectors={
            # disclosure stays enabled because T0 cannot be disabled and the Policy
            # validator refuses to construct a policy that tries. It is output-side, so
            # it has no effect on the input scans below.
            name: DetectorPolicy(
                enabled=name in ALWAYS_ON or name in ("secrets", "disclosure"),
                on_fail="block",
            )
            for name in CATALOGUE
        },
    )
    node = guard_node(blocking, "input", blocked_node="refused")
    update = node({"messages": [{"role": "user", "content": "AKIAIOSFODNN7EXAMPLE"}]})
    assert update["next"] == "refused"
    # The original text is returned on a block, so the graph does not act on a half
    # redacted string.
    assert "messages" not in update


def test_the_langgraph_node_leaves_a_clean_message_alone() -> None:
    from flowx_border.adapters.langgraph import guard_node

    node = guard_node(a_policy(), "input")
    update = node({"messages": [{"role": "user", "content": "hello"}]})
    assert "messages" not in update


def test_the_langgraph_node_tolerates_an_empty_state() -> None:
    from flowx_border.adapters.langgraph import guard_node

    node = guard_node(a_policy(), "input")
    assert node({}) == {}
    assert node({"messages": []}) == {}


# ------------------------------------------------------------------------ fastapi


def test_the_fastapi_dependency_scans_and_redacts() -> None:
    fastapi = pytest.importorskip("fastapi", reason="fastapi is a dev-only dependency")
    from fastapi.testclient import TestClient

    from flowx_border.adapters.fastapi import guard_dependency

    app = fastapi.FastAPI()
    guard = guard_dependency(a_policy(), field="prompt")

    @app.post("/chat")
    async def chat(decision=fastapi.Depends(guard)) -> dict[str, str]:
        return {"text": decision.text if decision else ""}

    client = TestClient(app)
    clean = client.post("/chat", json={"prompt": "what are your hours?"})
    assert clean.status_code == 200
    assert clean.json()["text"] == "what are your hours?"

    dirty = client.post("/chat", json={"prompt": "key AKIAIOSFODNN7EXAMPLE"})
    assert dirty.status_code == 200
    assert "AKIA" not in dirty.json()["text"]


def test_the_fastapi_dependency_returns_422_on_a_block() -> None:
    """A refusal is a normal guard outcome, not a server fault.

    A 5xx would page somebody for a request that worked exactly as designed.
    """
    fastapi = pytest.importorskip("fastapi", reason="fastapi is a dev-only dependency")
    from fastapi.testclient import TestClient

    from flowx_border.adapters.fastapi import BLOCKED_STATUS, guard_dependency
    from flowx_border.policy import DetectorPolicy, Policy

    blocking = Policy(
        policy_id="blocking",
        version=1,
        fail_mode=dict.fromkeys(("T0", "T1", "T2", "T3"), "open"),
        detectors={
            # disclosure stays enabled because T0 cannot be disabled and the Policy
            # validator refuses to construct a policy that tries. It is output-side, so
            # it has no effect on the input scans below.
            name: DetectorPolicy(
                enabled=name in ALWAYS_ON or name in ("secrets", "disclosure"),
                on_fail="block",
            )
            for name in CATALOGUE
        },
    )
    app = fastapi.FastAPI()

    @app.post("/chat")
    async def chat(
        decision=fastapi.Depends(guard_dependency(blocking)),
    ) -> dict[str, str]:
        return {"text": "unreachable"}

    response = TestClient(app).post("/chat", json={"prompt": "AKIAIOSFODNN7EXAMPLE"})
    assert response.status_code == BLOCKED_STATUS
    body = response.json()["detail"]
    assert body["record_id"]
    assert body["findings"][0]["detector"] == "secrets"


def test_the_blocked_body_carries_no_raw_text() -> None:
    """A 4xx body ends up in log aggregators and support tickets.

    So it gets the same treatment as the evidence record: identifiers and labels, never
    the text or the spans.
    """
    from flowx_border.adapters.fastapi import _blocked_body
    from flowx_border.engine import run_scan
    from flowx_border.registry import loaded_detectors

    marker = "AKIAIOSFODNN7EXAMPLE"
    decision = run_scan(
        f"my key is {marker}", "input", a_policy(), None, dict(loaded_detectors())
    )
    body = str(_blocked_body(decision))
    assert marker not in body
    assert "span" not in body


def test_a_request_that_is_not_json_passes_through() -> None:
    fastapi = pytest.importorskip("fastapi", reason="fastapi is a dev-only dependency")
    from fastapi.testclient import TestClient

    from flowx_border.adapters.fastapi import guard_dependency

    app = fastapi.FastAPI()

    @app.post("/chat")
    async def chat(
        decision=fastapi.Depends(guard_dependency(a_policy())),
    ) -> dict[str, bool]:
        return {"scanned": decision is not None}

    response = TestClient(app).post("/chat", content=b"not json at all")
    assert response.status_code == 200
    assert response.json()["scanned"] is False


# ------------------------------------------------------------------------ contract


def test_no_adapter_is_imported_by_the_package() -> None:
    """Importing flowx_border must not require LangGraph or FastAPI.

    Each adapter pulls in a framework the library does not depend on, so they stay
    opt-in imports.
    """
    import subprocess
    import sys

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import flowx_border, sys; print('fastapi' in sys.modules)",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "False"


def test_the_public_api_did_not_grow() -> None:
    import flowx_border

    assert flowx_border.__all__ == ["load_policy", "scan_input", "scan_output"]


def test_the_fastapi_middleware_blocks_a_request_field() -> None:
    """The middleware form, for retrofitting handlers you would rather not touch.

    Asserted on the request side because `secrets` is input-only, which the catalogue is
    right about: a credential in a model's output is output_leakage's business, not this
    detector's. The response side is covered by the pii test below.
    """
    fastapi = pytest.importorskip("fastapi", reason="fastapi is a dev-only dependency")
    from fastapi.testclient import TestClient

    from flowx_border.adapters.fastapi import BLOCKED_STATUS, guard_middleware
    from flowx_border.policy import DetectorPolicy, Policy

    blocking = Policy(
        policy_id="mw-blocking",
        version=1,
        fail_mode=dict.fromkeys(("T0", "T1", "T2", "T3"), "open"),
        detectors={
            name: DetectorPolicy(
                enabled=name in ALWAYS_ON or name in ("secrets", "disclosure"),
                on_fail="block",
            )
            for name in CATALOGUE
        },
    )
    app = fastapi.FastAPI()
    app.add_middleware(guard_middleware(blocking))

    @app.post("/chat")
    async def chat() -> dict[str, str]:
        return {"completion": "unreachable"}

    response = TestClient(app).post("/chat", json={"prompt": "AKIAIOSFODNN7EXAMPLE"})
    assert response.status_code == BLOCKED_STATUS
    assert response.json()["record_id"]


def test_the_fastapi_middleware_redacts_a_response_field() -> None:
    """End to end on the output side, which needs a model-backed detector."""
    fastapi = pytest.importorskip("fastapi", reason="fastapi is a dev-only dependency")
    from fastapi.testclient import TestClient

    from flowx_border.adapters.fastapi import guard_middleware
    from flowx_border.detectors.pii import PiiDetector
    from flowx_border.models.registry import ModelUnavailableError
    from flowx_border.policy import DetectorPolicy, Policy

    try:
        PiiDetector().warm()
    except ModelUnavailableError as error:
        pytest.skip(f"piiguard weights not cached: {error}")

    redacting = Policy(
        policy_id="mw-redacting",
        version=1,
        fail_mode=dict.fromkeys(("T0", "T1", "T2", "T3"), "open"),
        detectors={
            name: DetectorPolicy(
                enabled=name in ALWAYS_ON or name in ("secrets", "disclosure", "pii"),
                on_fail="redact",
            )
            for name in CATALOGUE
        },
    )
    app = fastapi.FastAPI()
    app.add_middleware(guard_middleware(redacting, response_field="completion"))

    @app.post("/chat")
    async def chat() -> dict[str, str]:
        return {"completion": "Your advisor is Marie Dubois."}

    body = TestClient(app).post("/chat", json={"prompt": "who is my advisor?"}).json()
    assert "Marie Dubois" not in body["completion"]
    assert "[PERSON]" in body["completion"]


def test_the_middleware_passes_a_non_json_response_through_byte_for_byte() -> None:
    """Middleware that ate a response it could not parse would break every download."""
    fastapi = pytest.importorskip("fastapi", reason="fastapi is a dev-only dependency")
    from fastapi.responses import PlainTextResponse
    from fastapi.testclient import TestClient

    from flowx_border.adapters.fastapi import guard_middleware

    app = fastapi.FastAPI()
    app.add_middleware(guard_middleware(a_policy()))

    @app.get("/csv")
    async def csv() -> PlainTextResponse:
        return PlainTextResponse("a,b,c\n1,2,3\n")

    response = TestClient(app).get("/csv")
    assert response.status_code == 200
    assert response.text == "a,b,c\n1,2,3\n"


def test_the_middleware_only_touches_the_paths_it_was_given() -> None:
    # Scanning a health check costs a model pass, so narrowing matters.
    fastapi = pytest.importorskip("fastapi", reason="fastapi is a dev-only dependency")
    from fastapi.testclient import TestClient

    from flowx_border.adapters.fastapi import guard_middleware

    app = fastapi.FastAPI()
    app.add_middleware(guard_middleware(a_policy(), paths=("/chat",)))

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"completion": "AKIAIOSFODNN7EXAMPLE"}

    # Outside the configured paths, so it is not scanned and not redacted.
    assert "AKIA" in TestClient(app).get("/healthz").json()["completion"]


# ------------------------------------------- scanners that gained a home on 2026-08-11


#: Every scanner llm-guard shipped. Pinned as a count so that a scanner disappearing
#: from both tables fails here.
#:
#: This test exists because exactly that happened while the six below were being moved:
#: a search-and-replace took `Regex` and `ReadingTime` out of SUPPORTED instead of
#: UNSUPPORTED, and for a few minutes they were in neither. Nothing caught it. The doc
#: test iterates the union of the two tables, so a scanner missing from both is missing
#: from the assertion as well, and the shim would have raised "not a known llm-guard
#: scanner" for a check it performs.
LLM_GUARD_SCANNER_COUNT = 27

NEWLY_SUPPORTED = {
    "BanSubstrings": "banned_terms",
    "BanCompetitors": "banned_terms",
    "JSON": "output_format",
    "Regex": "output_format",
    "ReadingTime": "output_format",
    "URLReachability": "url_reachability",
}


def test_every_llm_guard_scanner_is_in_exactly_one_table() -> None:
    assert len(SUPPORTED) + len(UNSUPPORTED) == LLM_GUARD_SCANNER_COUNT
    assert not set(SUPPORTED) & set(UNSUPPORTED)


@pytest.mark.parametrize("scanner", sorted(NEWLY_SUPPORTED))
def test_a_scanner_that_gained_a_detector_is_no_longer_refused(scanner: str) -> None:
    assert scanner not in UNSUPPORTED
    assert SUPPORTED[scanner] == NEWLY_SUPPORTED[scanner]


def test_token_limit_maps_to_the_detector_rather_than_to_output_format() -> None:
    """The mapping that was almost made wrong, and the one that is now right.

    This test used to assert TokenLimit stayed refused, and it was right to do so:
    the tempting mapping was onto `output_format.max_length`, which counts graphemes
    and words. A token count is a different unit, and reporting a different number
    from the one the caller asked about is the "approximately right is worse than
    absent" failure this module's header warns about.

    What changed on 2026-08-12 is not that objection, which still holds, but that the
    library stopped needing to guess the tokenizer: `token_limit` makes the policy name
    one and pin it. So the mapping goes to the detector that counts tokens, and never to
    the one that counts graphemes.
    """
    assert SUPPORTED["TokenLimit"] == "token_limit"
    assert "TokenLimit" not in UNSUPPORTED
    assert SUPPORTED["TokenLimit"] != "output_format", (
        "the unit objection has not gone away, only the reason the library could not "
        "answer in the right unit"
    )


def test_malicious_urls_is_still_refused_and_says_why_reachability_is_not_it() -> None:
    # url_reachability asks whether a link answers. That is a different question from
    # whether it is hostile.
    assert "MaliciousURLs" not in SUPPORTED
    assert "different question" in UNSUPPORTED["MaliciousURLs"]


def test_a_scanner_needing_configuration_raises_without_a_policy() -> None:
    """The alternative would be a clean-looking tuple for a check that never ran.

    `banned_terms` with no terms reports `terms_not_configured` and finds nothing, so
    accepting the call would hand back `valid=True` for a competitor list nobody
    supplied.
    """
    from flowx_border.adapters.llm_guard_compat import (
        NEEDS_POLICY,
        UnconfiguredScannerError,
    )

    for scanner in NEEDS_POLICY:
        with pytest.raises(UnconfiguredScannerError, match="only a policy can carry"):
            scan_prompt("some text", [scanner])


def test_the_error_names_the_option_to_set() -> None:
    from flowx_border.adapters.llm_guard_compat import UnconfiguredScannerError

    with pytest.raises(UnconfiguredScannerError, match=r"banned_terms\.options\.terms"):
        scan_prompt("some text", ["BanSubstrings"])


def test_every_scanner_needing_a_policy_is_one_this_shim_supports() -> None:
    from flowx_border.adapters.llm_guard_compat import NEEDS_POLICY

    assert set(NEEDS_POLICY) <= set(SUPPORTED)


def test_a_configured_scanner_runs_and_finds_what_it_was_given() -> None:
    """End to end through the shim, with the policy carrying what the constructor used
    to."""
    from flowx_border.policy import DetectorPolicy, Policy

    policy = Policy(
        policy_id="compat",
        version=1,
        fail_mode=dict.fromkeys(("T0", "T1", "T2", "T3"), "open"),
        detectors={
            "banned_terms": DetectorPolicy(
                enabled=True,
                on_fail="flag",
                options={"terms": ["Acme"], "whole_words": True},
            ),
            "disclosure": DetectorPolicy(enabled=True, on_fail="log"),
        },
    )
    _text, valid, scores = scan_output(
        "who is the competition?",
        "Acme is the competition.",
        ["BanCompetitors"],
        policy,
    )
    assert valid["banned_terms"] is False
    assert scores["banned_terms"] == 1.0


def test_a_scanner_needing_no_configuration_still_works_without_a_policy() -> None:
    # URLReachability has usable defaults, so it is not in NEEDS_POLICY and a bare call
    # is accepted. No link in the text, so nothing is requested and the guard in
    # conftest stays satisfied.
    _text, valid, _scores = scan_output(
        "q", "An answer with no links in it.", ["URLReachability"]
    )
    assert valid["url_reachability"] is True
