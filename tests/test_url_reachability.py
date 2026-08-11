# SPDX-License-Identifier: Apache-2.0
"""Tests for the url_reachability detector.

This is the only test file in the suite that opens a socket, so it is worth being
precise about what that means. Every test that makes a request is marked
`@pytest.mark.network`, which lifts the guard in conftest.py, and every one of them
talks to a stub server on loopback started by a fixture in this file. None of them needs
the internet, so they are as deterministic as the rest of the suite and they run in CI.
The marker means "needs a socket", which is exactly what it says in conftest.

The tests that do not need a socket are the interesting ones anyway: URL extraction,
the internationalised-URL conversion, and the private-address refusal are all pure
functions, and they are where the upstream validator's problems actually live.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.url_reachability import (
    UrlReachabilityDetector,
    UrlReachabilityError,
    resolves_to_private,
    urls_in,
    wire_url,
)
from flowx_border.types import Finding

DETECTOR = UrlReachabilityDetector()
CTX = Context()


def run(text: str, **options: object) -> list[Finding]:
    options.setdefault("allow_private", True)  # the stub server is on loopback
    return DETECTOR.run(text, DetectorConfig(on_fail="flag", options=options), CTX)


def labels(text: str, **options: object) -> list[str]:
    return [finding.label for finding in run(text, **options)]


# ------------------------------------------------------------------ the stub server


class _Handler(BaseHTTPRequestHandler):
    """Answers by path, so one server covers every status a test needs."""

    def _respond(self) -> None:
        path = self.path.split("?")[0]
        if path.startswith("/status/"):
            code = int(path.rsplit("/", 1)[-1])
        elif path == "/no-head" and self.command == "HEAD":
            code = 405
        elif path == "/no-head":
            code = 200
        else:
            code = 200
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    # BaseHTTPRequestHandler dispatches on these exact names, so the casing is the
    # stdlib's rather than a choice.
    do_GET = _respond  # noqa: N815
    do_HEAD = _respond  # noqa: N815

    def log_message(self, *args: Any) -> None:
        """Silence. The default handler writes every request to stderr."""


@pytest.fixture(scope="module")
def server() -> Any:
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_port}"
    httpd.shutdown()


# ---------------------------------------------------------- no socket needed for these


def test_urls_are_found_in_prose() -> None:
    assert urls_in("See https://example.com/a and http://example.org.", 5) == [
        "https://example.com/a",
        "http://example.org",
    ]


def test_trailing_sentence_punctuation_is_not_part_of_the_url() -> None:
    # The bug every URL regex has. A link at the end of a sentence is followed by a full
    # stop, and requesting `https://example.com.` is a different request.
    assert urls_in("Read https://example.com/guide.", 5) == [
        "https://example.com/guide"
    ]
    assert urls_in("Read (https://example.com/guide).", 5) == [
        "https://example.com/guide"
    ]


def test_a_repeated_url_costs_one_request() -> None:
    text = "https://example.com a https://example.com b https://example.com"
    assert urls_in(text, 5) == ["https://example.com"]


def test_no_urls_means_no_findings() -> None:
    assert run("An answer with no links in it at all.") == []


def test_the_url_limit_is_respected() -> None:
    text = " ".join(f"https://example{i}.com" for i in range(20))
    assert len(urls_in(text, 5)) == 5


# ------------------------------------------------------ internationalised URLs

#: One URL per language, each with a non-ASCII host, a non-ASCII path, or both. A
#: reachability check that does not convert these reports a working link as broken,
#: which is the worst outcome available for a detector whose whole output is a claim
#: about whether a link works.
IDN_URLS: dict[str, str] = {
    "de": "https://münchen.example/straße",
    "ro": "https://exemplu.example/informații",
    "bg": "https://пример.example/новини",
    "el": "https://παράδειγμα.example/οδηγός",
    "cs": "https://příklad.example/průvodce",
    "sk": "https://príklad.example/sprievodca",
    "pl": "https://przykład.example/przewodnik",
    "hu": "https://példa.example/útmutató",
    "fi": "https://esimerkki.example/käyttöopas",
    "sv": "https://exempel.example/vägledning",
    "da": "https://eksempel.example/vejledning",
    "et": "https://näide.example/juhend",
    "lv": "https://piemērs.example/rokasgrāmata",
    "lt": "https://pavyzdys.example/vadovas",
    "sl": "https://primer.example/vodnik",
    "hr": "https://primjer.example/vodič",
    "mt": "https://eżempju.example/gwida",
    "ga": "https://sampla.example/treoir",
    "tr": "https://örnek.example/kılavuz",
    "az": "https://nümunə.example/bələdçi",
    "fr": "https://exemple.example/guidé",
    "es": "https://ejemplo.example/guía",
    "pt": "https://exemplo.example/guião",
    "it": "https://esempio.example/guida",
    "nl": "https://voorbeeld.example/handleiding",
    "en": "https://example.example/guide",
}

CLAIMED = {
    "az",
    "bg",
    "cs",
    "da",
    "de",
    "el",
    "en",
    "es",
    "et",
    "fi",
    "fr",
    "ga",
    "hr",
    "hu",
    "it",
    "lt",
    "lv",
    "mt",
    "nl",
    "pl",
    "pt",
    "ro",
    "sk",
    "sl",
    "sv",
    "tr",
}


def test_the_fixtures_cover_every_language_the_project_claims() -> None:
    assert set(IDN_URLS) == CLAIMED


@pytest.mark.parametrize("code", sorted(IDN_URLS))
def test_a_url_in_each_language_converts_to_something_sendable(code: str) -> None:
    """The conversion is the multilingual work, and it is checkable without a socket.

    Whatever comes out has to be ASCII, or it cannot go on the wire at all.
    """
    wire = wire_url(IDN_URLS[code])
    wire.encode("ascii")  # raises if the conversion did not happen
    assert wire.startswith("https://"), code


def test_a_non_ascii_host_becomes_punycode() -> None:
    assert wire_url("https://münchen.example/x").startswith("https://xn--mnchen-3ya.")


def test_a_non_ascii_path_is_percent_encoded() -> None:
    assert wire_url("https://example.com/straße").endswith("/stra%C3%9Fe")


def test_an_ascii_url_is_left_alone() -> None:
    assert wire_url("https://example.com/a/b?c=d") == "https://example.com/a/b?c=d"


def test_the_fragment_is_dropped_because_it_never_reaches_the_server() -> None:
    assert wire_url("https://example.com/a#section") == "https://example.com/a"


def test_a_host_the_idna_codec_refuses_is_used_as_written() -> None:
    # Reported as unreachable when it fails to connect, which is true, rather than
    # discarded and reported as nothing, which would be a silent gap.
    assert "my_host" in wire_url("https://my_host.example/x")


# ----------------------------------------------------------------- refusing to fetch


def test_a_non_http_scheme_is_refused_rather_than_attempted() -> None:
    # `file://` reads the deployment's disk and `gopher://` is a request-smuggling
    # vector. Neither is something a link in an answer should be.
    assert labels("See file:///etc/passwd for details.") == ["url_blocked_scheme"]
    assert labels("See gopher://example.com/1 for details.") == ["url_blocked_scheme"]


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/admin",
        "http://localhost:6379/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/internal",
        "http://192.168.1.1/router",
        "http://[::1]/admin",
    ],
)
@pytest.mark.network
def test_a_private_address_is_refused_by_default(url: str) -> None:
    """The server-side request forgery the upstream validator performs on request.

    Every one of these is a real target: 169.254.169.254 is cloud instance metadata and
    returns credentials, and 6379 is a Redis nobody meant to expose. The upstream
    validator fetches whatever the model emitted, from inside the deployment's network.

    Marked `network` because refusing requires resolving the name, which is a socket
    operation even though no connection is ever made.
    """
    found = DETECTOR.run(f"Try {url} for that.", DetectorConfig(on_fail="flag"), CTX)
    assert [f.label for f in found] == ["url_private_address"], url


@pytest.mark.network
def test_a_private_address_can_be_allowed_for_an_intranet_deployment() -> None:
    assert resolves_to_private("127.0.0.1") is True
    found = DETECTOR.run(
        "Try http://127.0.0.1:1/x",
        DetectorConfig(on_fail="flag", options={"allow_private": True}),
        CTX,
    )
    # Allowed through, so it is attempted and fails to connect rather than being
    # refused before the request.
    assert [f.label for f in found] == ["url_unreachable"]


# --------------------------------------------------------------- against a real socket


@pytest.mark.network
def test_a_reachable_url_produces_no_finding(server: str) -> None:
    assert run(f"See {server}/ok for details.") == []


@pytest.mark.network
def test_an_unreachable_host_is_reported(server: str) -> None:
    # Port 1 on loopback, which nothing is listening on.
    assert labels("See http://127.0.0.1:1/nothing here.") == ["url_unreachable"]


@pytest.mark.network
def test_an_error_status_is_a_different_finding_from_unreachable(server: str) -> None:
    # Upstream reports both as the same failure. They are different facts and a caller
    # may want to act on them differently.
    assert labels(f"See {server}/status/404 here.") == ["url_error_status"]
    assert labels(f"See {server}/status/500 here.") == ["url_error_status"]


@pytest.mark.network
def test_a_redirect_counts_as_reachable(server: str) -> None:
    """Upstream accepts only 200, so it reports a permanent redirect as unreachable.

    The endpoint answered, which is the question being asked. Redirects are not
    followed, because following them means re-running the private-address check at
    every hop or not at all, and the second is how a public URL becomes a request to a
    metadata endpoint.
    """
    assert run(f"See {server}/status/301 here.") == []
    assert run(f"See {server}/status/302 here.") == []


@pytest.mark.network
def test_a_204_counts_as_reachable(server: str) -> None:
    assert run(f"See {server}/status/204 here.") == []


@pytest.mark.network
def test_a_server_that_refuses_head_is_rechecked_with_get(server: str) -> None:
    # 405 is how a server says it dislikes HEAD, not that the URL does not exist.
    assert run(f"See {server}/no-head here.") == []


@pytest.mark.network
def test_a_policy_can_state_which_statuses_count(server: str) -> None:
    assert labels(f"See {server}/status/301 here.", ok_statuses=[200]) == [
        "url_error_status"
    ]


@pytest.mark.network
def test_several_urls_are_all_checked(server: str) -> None:
    text = f"Both {server}/status/404 and {server}/status/500 are cited."
    assert labels(text) == ["url_error_status", "url_error_status"]


# ------------------------------------------------------------------- the deadline


@pytest.mark.network
def test_the_deadline_is_total_rather_than_per_url(server: str) -> None:
    """A per-request timeout multiplied by the number of URLs is not a budget.

    A model can emit fifty links. With per-request timeouts the detector's worst case is
    fifty times the timeout, which is a scan that never returns in any useful sense.
    """
    import time

    text = " ".join(f"http://127.0.0.1:1/{i}" for i in range(5))
    started = time.monotonic()
    found = DETECTOR.run(
        text,
        DetectorConfig(
            on_fail="flag", options={"deadline_ms": 300, "allow_private": True}
        ),
        CTX,
    )
    elapsed_ms = (time.monotonic() - started) * 1000.0
    assert elapsed_ms < 3000, f"the deadline did not bound the detector: {elapsed_ms}"
    assert found, "something must be reported rather than nothing"


def test_urls_left_unchecked_are_reported_as_incomplete() -> None:
    """A partial check has to say it was partial.

    Reporting nothing for the URLs that were not reached would be indistinguishable
    from reporting that they were fine, which is the failure this library refuses
    everywhere else.
    """
    found = DETECTOR.run(
        "http://127.0.0.1:1/a http://127.0.0.1:1/b",
        # A deadline this small expires before the first request, so both are unchecked.
        DetectorConfig(
            on_fail="flag",
            options={"deadline_ms": 0.001, "allow_private": True},
        ),
        CTX,
    )
    assert [f.label for f in found] == ["url_check_incomplete"] * 2
    assert all(f.action == "log" for f in found)


def test_a_zero_deadline_raises_rather_than_silently_checking_nothing() -> None:
    with pytest.raises(UrlReachabilityError, match="deadline_ms must be above 0"):
        DETECTOR.run(
            "https://example.com",
            DetectorConfig(on_fail="flag", options={"deadline_ms": 0}),
            CTX,
        )


def test_an_invalid_ok_statuses_raises() -> None:
    with pytest.raises(UrlReachabilityError, match="list of integers"):
        DETECTOR.run(
            "https://example.com",
            DetectorConfig(on_fail="flag", options={"ok_statuses": ["fine"]}),
            CTX,
        )


# --------------------------------------------------------------------------- packaging


def test_the_detector_is_outside_core_and_declares_why() -> None:
    from flowx_border.detectors.catalogue import CATALOGUE, CORE

    assert "url_reachability" not in CORE
    assert CATALOGUE["url_reachability"].requires == {"network"}


def test_enabling_it_produces_a_deployment_note() -> None:
    from flowx_border.policy import DetectorPolicy, Policy
    from flowx_border.registry import deployment_notes

    policy = Policy(
        policy_id="links",
        version=1,
        fail_mode=dict.fromkeys(("T0", "T1", "T2", "T3"), "open"),
        detectors={
            # Every non-CORE detector named explicitly, so this asserts about
            # url_reachability rather than about however many others exist today.
            name: DetectorPolicy(enabled=name == "url_reachability")
            for name in ("url_reachability", "sql_injection", "json_schema")
        },
    )
    notes = deployment_notes(policy)
    assert len(notes) == 1
    assert notes[0].startswith("network:")
    assert "url_reachability" in notes[0]


def test_the_shipped_policies_leave_it_off() -> None:
    from pathlib import Path

    from flowx_border import load_policy

    policies = Path(__file__).resolve().parent.parent / "policies"
    for path in sorted(policies.glob("*.yaml")):
        assert load_policy(path).enabled_for("url_reachability") is False, path.name


def test_warming_it_makes_no_request() -> None:
    """A deployment that warms every detector must not thereby make egress.

    Not marked `network`: the guard in conftest is active here, so a request would fail
    the test rather than pass it quietly.
    """
    DETECTOR.warm()
    DETECTOR.warm()


# --------------------------------------------------------------------------- plumbing


def test_the_detector_matches_the_catalogue() -> None:
    from flowx_border.detectors.catalogue import CATALOGUE

    spec = CATALOGUE["url_reachability"]
    assert (DETECTOR.id, DETECTOR.tier) == ("url_reachability", spec.tier)
    assert DETECTOR.sides == spec.sides


def test_it_runs_only_on_escalation_unless_the_policy_says_always() -> None:
    # T3 semantics, and the reason this detector is T3: a network round trip does not
    # belong on the standard path.
    from flowx_border.detectors.catalogue import CATALOGUE

    assert CATALOGUE["url_reachability"].tier == "T3"


def test_no_finding_carries_a_span() -> None:
    assert all(f.span is None for f in labels_findings())


def labels_findings() -> list[Finding]:
    return DETECTOR.run(
        "See file:///etc/passwd here.", DetectorConfig(on_fail="flag"), CTX
    )


def test_findings_never_carry_the_text() -> None:
    for finding in labels_findings():
        assert "passwd" not in finding.model_dump_json()
