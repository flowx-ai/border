# SPDX-License-Identifier: Apache-2.0
"""T3: do the links in the answer actually go anywhere?

Ports the Guardrails Hub `endpoint_is_reachable` validator. A model that invents a
plausible-looking documentation link is a common and expensive failure: the answer looks
right, the user follows the link, and the trust goes with it.

**This is the first detector that leaves the machine.** It declares
`requires={"network"}`, so `registry.deployment_notes` tells a caller who enables it
that they have put a third party in the latency path of every scan. It is disabled in
both shipped policies, and `tests/test_offline.py` excludes it by definition: the claim
that a scan works with the interface down is a claim about `CORE`, and this is not in
`CORE`.

Three things upstream does that this cannot
--------------------------------------------

**No timeout.** Upstream is `requests.get(value)` with no `timeout=`. A host that
accepts a connection and never replies hangs the scan, and therefore the request the
scan is inside, indefinitely. That is not a slow detector, it is a stuck process, and it
is reachable by any model output naming a host an attacker controls.

**No egress restriction, on a URL the model chose.** Fetching a URL that came out of a
language model, from inside the deployment's network, is a server-side request forgery
primitive. A prompt-injected model that emits `http://169.254.169.254/latest/meta-data/`
gets the library to read cloud instance credentials; `http://localhost:6379/` reaches a
Redis nobody meant to expose. So this resolves each host first and refuses anything that
lands on a private, loopback, link-local, reserved or multicast address, unless a policy
sets `allow_private: true`, which exists because some deployments genuinely check their
own intranet links.

The residual risk, stated because it is not fixed here: the check resolves the name and
then makes the request by name, so a DNS entry that answers differently on the second
lookup can still get through. Closing that means connecting to the resolved address and
carrying the Host header, which is a bigger change to how the request is made. A
deployment that considers rebinding part of its threat model should not enable this
detector.

**Only 200 counts.** Upstream reports anything other than `200 OK` as a failure, so a
permanent redirect, a `204`, or a `206` is "unreachable" when the endpoint plainly
exists. Here a connection failure is `url_unreachable` and an HTTP error status is
`url_error_status`, because those are different facts and a caller may want to act on
them differently. Redirects are not followed, and a redirect counts as reachable: the
endpoint answered.

Where the 26 languages come in
------------------------------

A URL is not ASCII. `https://münchen.example/straße` has a non-ASCII host and a
non-ASCII path, and neither can go on the wire as written: the host has to be punycode
and the path has to be percent-encoded UTF-8. A reachability check that skips that step
reports a perfectly good link as unreachable, which is the worst outcome available here,
because the detector's entire output is a claim about whether a link works. Nine of the
26 languages routinely produce URLs like this. `_wire_url` does the conversion and there
is a fixture for each language.

The budget is a deadline, not a measurement
--------------------------------------------

Every other detector's budget is a number somebody measured. This one cannot be: it
depends on a network the library does not control. So the budget is enforced rather than
observed. `deadline_ms` is a total across all URLs in one scan, not a per-request
timeout, because per-request timeouts multiply by the number of URLs and a model can
emit fifty. When the deadline runs out, or has less left than a request could
plausibly use, the remaining URLs are reported as `url_check_incomplete` at action
`log`, so a partial check says it was partial rather than looking like a clean one.

T3 for the same reason `groundedness` is: it is the expensive tier, it runs only when a
lower tier flags, and a policy that wants it on every scan says `always: true` and has
read what that costs.

Options
-------

    deadline_ms:    total wall clock for the whole detector, default 2000
    max_urls:       how many to check in one scan, default 5
    allow_private:  check hosts that resolve to a private address, default false
    ok_statuses:    HTTP statuses that count as reachable, default 2xx and 3xx
"""

from __future__ import annotations

import ipaddress
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Final

from flowx_border.detectors.base import OUTPUT, Context, DetectorConfig
from flowx_border.types import Finding

#: Schemes worth checking. Everything else is refused rather than attempted: `file://`
#: reads the deployment's disk and `gopher://` is a classic request-smuggling vector,
#: and neither is something a link in an answer should be.
_ALLOWED_SCHEMES: Final[frozenset[str]] = frozenset({"http", "https"})

#: URLs in prose. Permissive on the host so an internationalised name is found, and
#: trailing punctuation is trimmed below rather than matched, because a link at the end
#: of a sentence is followed by a full stop that is not part of it.
_URL: Final = re.compile(r"\b(?:https?|ftp|file|gopher)://[^\s<>\"'`]+", re.IGNORECASE)

#: Characters that end a sentence rather than a URL.
_TRAILING: Final = ".,;:!?)]}'\"»”’"

DEFAULT_DEADLINE_MS: Final = 2000.0
DEFAULT_MAX_URLS: Final = 5
#: Per request, and always clamped to whatever is left of the deadline.
_PER_REQUEST_CEILING_S: Final = 5.0

#: The least time worth starting a request with. Below this the attempt cannot
#: succeed, and it still costs a DNS lookup and a socket to learn nothing, so the
#: URL is reported as unchecked instead. Without a floor, a deadline with a sliver
#: left opens a connection with a microsecond timeout, which is a request made
#: purely to fail.
_MIN_SLICE_S: Final = 0.01

_USER_AGENT: Final = "flowx-border url_reachability"


class UrlReachabilityError(ValueError):
    """The policy asked for a check that cannot be performed as written."""


def urls_in(text: str, limit: int) -> list[str]:
    """URLs in the text, trailing sentence punctuation trimmed, in order, deduplicated.

    Deduplicated because a model repeating one link three times should cost one request,
    not three, and the finding is about the link rather than about where it appeared.
    """
    seen: list[str] = []
    for match in _URL.finditer(text):
        candidate = match.group().rstrip(_TRAILING)
        if candidate and candidate not in seen:
            seen.append(candidate)
        if len(seen) >= limit:
            break
    return seen


def wire_url(url: str) -> str:
    """The form that can go on the wire: punycode host, percent-encoded path.

    `https://münchen.example/straße` is a valid URL and cannot be sent as written. A
    check that skips this reports a working link as broken, which is the failure this
    detector most needs to avoid, since its whole output is a claim about whether a link
    works.
    """
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    try:
        encoded_host = host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        # A host the IDNA codec refuses is used as written. Letting it through to fail
        # at connect time reports `url_unreachable`, which is true, rather than
        # discarding the URL and reporting nothing, which would be a silent gap.
        encoded_host = host

    netloc = encoded_host
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    if parts.username:
        credentials = parts.username
        if parts.password:
            credentials = f"{credentials}:{parts.password}"
        netloc = f"{credentials}@{netloc}"

    return urllib.parse.urlunsplit(
        (
            parts.scheme.lower(),
            netloc,
            urllib.parse.quote(parts.path, safe="/%:@!$&'()*+,;=~-._"),
            urllib.parse.quote(parts.query, safe="/?=&%:@!$'()*+,;~-._"),
            "",  # the fragment never reaches the server
        )
    )


def resolves_to_private(host: str) -> bool:
    """Whether every address this host resolves to is one we refuse to request.

    Any public address is enough to proceed, and a host that does not resolve is not
    private: it will fail at connect time and be reported as unreachable, which is the
    honest answer rather than a made-up one.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except (OSError, UnicodeError):
        return False

    addresses = []
    for info in infos:
        raw = info[4][0]
        try:
            addresses.append(ipaddress.ip_address(raw))
        except ValueError:  # pragma: no cover - getaddrinfo returns parseable addresses
            continue
    if not addresses:
        return False
    return all(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
        for address in addresses
    )


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Turns a redirect into an HTTPError instead of following it.

    Not following is a security decision as much as a semantic one. Following means
    re-running the private-address check at every hop or not at all, and the second is
    how a public URL becomes a request to a metadata endpoint. A redirect also answers
    the question being asked: something is there.
    """

    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        """Returning None is how this handler says "do not follow"."""
        return None


class UrlReachabilityDetector:
    """Checks that links in the output resolve to something that answers."""

    id = "url_reachability"
    tier = "T3"
    sides = frozenset({OUTPUT})

    def warm(self) -> None:
        """Nothing to load, and deliberately no probe request.

        `warm` runs at start-up on every deployment that warms its detectors, and a
        detector that made a network request there would turn a warm-up into egress
        nobody asked for.
        """

    def run(
        self,
        text: str,
        cfg: DetectorConfig,
        ctx: Context,  # noqa: ARG002 - the Detector protocol fixes this signature
    ) -> list[Finding]:
        options = cfg.options
        deadline_ms = float(options.get("deadline_ms", DEFAULT_DEADLINE_MS))
        if deadline_ms <= 0:
            raise UrlReachabilityError(
                "url_reachability deadline_ms must be above 0. A deadline of zero "
                "would report every link as unchecked, which is a slower way of "
                "disabling the detector than disabling it."
            )
        max_urls = int(options.get("max_urls", DEFAULT_MAX_URLS))
        allow_private = bool(options.get("allow_private", False))
        ok_statuses = self._ok_statuses(options)

        found = urls_in(text, max_urls)
        if not found:
            return []

        deadline = time.monotonic() + deadline_ms / 1000.0
        out: list[Finding] = []

        for url in found:
            remaining = deadline - time.monotonic()
            if remaining < _MIN_SLICE_S:
                # Say the check did not finish rather than letting an unchecked URL look
                # like a checked one. The floor is why this is `<` rather than `<= 0`:
                # a request that cannot possibly complete is not worth the socket.
                out.append(self._finding("url_check_incomplete", cfg, action="log"))
                continue
            label = self._check(url, remaining, allow_private, ok_statuses)
            if label is not None:
                out.append(self._finding(label, cfg))
        return out

    def _ok_statuses(self, options: dict[str, Any]) -> frozenset[int] | None:
        raw = options.get("ok_statuses")
        if raw is None:
            return None  # the default 2xx and 3xx test is applied in `_check`
        try:
            return frozenset(int(status) for status in raw)
        except (TypeError, ValueError) as error:
            raise UrlReachabilityError(
                f"url_reachability ok_statuses must be a list of integers: {error}"
            ) from error

    def _check(
        self,
        url: str,
        remaining_s: float,
        allow_private: bool,
        ok_statuses: frozenset[int] | None,
    ) -> str | None:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme.lower() not in _ALLOWED_SCHEMES:
            return "url_blocked_scheme"

        host = parts.hostname
        if not host:
            return "url_unreachable"

        if not allow_private and resolves_to_private(host):
            return "url_private_address"

        timeout = min(remaining_s, _PER_REQUEST_CEILING_S)
        opener = urllib.request.build_opener(_NoRedirects)
        request = urllib.request.Request(  # noqa: S310 - scheme is checked above
            wire_url(url), method="HEAD", headers={"User-Agent": _USER_AGENT}
        )

        try:
            with opener.open(request, timeout=timeout) as response:
                status = int(response.status)
        except urllib.error.HTTPError as error:
            status = int(error.code)
            # A HEAD that the server refuses to answer is not evidence about the URL.
            # Retrying once as GET is what separates "this endpoint does not exist" from
            # "this server dislikes HEAD", and 405 and 501 are how it says the latter.
            if status in (405, 501):
                return self._recheck_with_get(url, remaining_s, ok_statuses)
        except (urllib.error.URLError, OSError, ValueError):
            return "url_unreachable"

        return self._classify(status, ok_statuses)

    def _recheck_with_get(
        self, url: str, remaining_s: float, ok_statuses: frozenset[int] | None
    ) -> str | None:
        timeout = min(remaining_s, _PER_REQUEST_CEILING_S)
        opener = urllib.request.build_opener(_NoRedirects)
        # S310: the scheme is checked by the caller before this is reached.
        request = urllib.request.Request(  # noqa: S310
            wire_url(url), method="GET", headers={"User-Agent": _USER_AGENT}
        )
        try:
            with opener.open(request, timeout=timeout) as response:
                # The body is not read. This detector answers whether something is
                # there, and downloading a file to find that out would make a scan's
                # cost a function of what the model linked to.
                return self._classify(int(response.status), ok_statuses)
        except urllib.error.HTTPError as error:
            return self._classify(int(error.code), ok_statuses)
        except (urllib.error.URLError, OSError, ValueError):
            return "url_unreachable"

    def _classify(self, status: int, ok_statuses: frozenset[int] | None) -> str | None:
        if ok_statuses is not None:
            return None if status in ok_statuses else "url_error_status"
        # 2xx and 3xx both mean something is there, which is the question. Upstream
        # accepts only 200, so it reports a permanent redirect as unreachable.
        return None if 200 <= status < 400 else "url_error_status"

    def _finding(
        self, label: str, cfg: DetectorConfig, action: str | None = None
    ) -> Finding:
        return Finding(
            detector_id=self.id,
            tier=self.tier,
            label=label,
            # 1.0. Whether a request got an answer is not a probabilistic judgement.
            score=1.0,
            # No span. A URL that does not resolve is a fact about the link rather than
            # about a place in the text, and redacting the characters would leave an
            # answer that silently lost its citation.
            span=None,
            action=action or cfg.on_fail,
        )
