# SPDX-License-Identifier: Apache-2.0
"""T1: internal hostnames in an answer that was meant for someone outside.

Ported from the Guardrails Hub `internal_domains` validator. The idea is sound and
narrow, which is why it survived the cut: an answer naming `wiki.corp.internal` has
disclosed a piece of your topology, and no model-backed detector is going to know that
`corp.internal` is yours.

The list is policy, and an empty one is reported
------------------------------------------------

Only the deploying organisation knows its own domains, so `options.domains` has no
useful default. An enabled detector with an empty list reports
`domains_not_configured` with action `log` and finds nothing else, rather than
reporting a clean scan. A scan that looked for nothing and a scan that found nothing
produce identical output, and the caller will read the second. `log` keeps it out of
the verdict; the shipped policies leave this detector off until there is a list.

Three bugs in the original, and one gap
---------------------------------------

Upstream builds `rf"https?://(?:\\w+\\.)*{re.escape(domain)}(?:/[\\w\\-/]*)?|..."` and
runs it with no boundary on either end.

**No left boundary.** Banning `example.com` also matches inside `notexample.com`, which
is somebody else's domain and usually a real one. Here a match must not be preceded by
a hostname character, and subdomains are reached through an explicit label prefix
instead.

**No right boundary.** `example.com` matches inside `example.com.evil.net`, an
attacker-controlled host that merely starts with your domain. That is the shape of a
phishing name, so reporting it as your internal domain is precisely backwards. Here a
match may not be followed by another label.

**The fix replaces every occurrence.** `on_fix.replace(domain, "*" * len(domain))`
rewrites the whole string rather than the span that matched, so a domain appearing in
a URL the answer legitimately cited is masked along with the leak. This detector
reports spans and lets the engine redact them, which it does right to left for the
reason engine.py sets out.

**The gap: internationalised domain names.** A domain is one host whether it is written
`münchen.example` or `xn--mnchen-3ya.example`, and a leak is just as much a leak in the
punycode spelling. Neither form matches the other as a string, so both are generated
from whichever one the policy gives and both are searched. Without this, a policy in
any of the 26 languages that has a non-ASCII internal domain gets a detector that
matches half of its own traffic. Domains that the IDNA codec rejects are used as
written rather than dropped, because a domain nobody can encode is still a domain
somebody can leak.

Budget is 5 ms at p95 at the reference input: one folding pass and one alternation.
"""

from __future__ import annotations

import re
from contextlib import suppress
from functools import lru_cache
from typing import Final

from flowx_border.detectors.base import OUTPUT, Context, DetectorConfig
from flowx_border.detectors.multilingual import fold
from flowx_border.types import Finding

LABEL: Final = "internal_domain"

#: Characters that continue a hostname. Used on both sides of a match so that a domain
#: is matched as a whole host rather than as a substring of a different one.
_HOST_CHAR: Final = r"[\w-]"


def idn_variants(domain: str) -> tuple[str, ...]:
    """A domain plus its other spelling, Unicode or punycode.

    Both are returned whichever way the policy wrote it, because the answer being
    scanned was written by a model that had no reason to pick the same one. Encoding
    failures are swallowed on purpose: the IDNA codec rejects labels this library has
    no business rejecting, an underscore in an internal hostname being the common case,
    and losing such a domain from the list would be a silent gap in a security check.
    """
    out = {domain}
    with suppress(UnicodeError, ValueError):
        out.add(domain.encode("idna").decode("ascii"))
    with suppress(UnicodeError, ValueError):
        out.add(domain.encode("ascii").decode("idna"))
    return tuple(sorted(out))


@lru_cache(maxsize=128)
def compile_domains(domains: tuple[str, ...]) -> re.Pattern[str] | None:
    """One alternation matching each domain as a whole host, subdomains included.

    `(?:label\\.)*` is what lets `wiki.corp.internal` match a policy that listed
    `corp.internal`, which is the behaviour anyone configuring this expects. The
    lookarounds are what stop `notcorp.internal` and `corp.internal.evil.net` from
    matching it, which is the behaviour they expect too and the original does not have.
    """
    spellings = sorted(
        {variant for domain in domains for variant in idn_variants(domain) if variant},
        key=len,
        reverse=True,
    )
    if not spellings:
        return None
    body = "|".join(re.escape(spelling) for spelling in spellings)
    return re.compile(
        rf"(?<!{_HOST_CHAR})(?<!\.)(?:{_HOST_CHAR}+\.)*(?:{body})"
        rf"(?!{_HOST_CHAR})(?!\.{_HOST_CHAR})"
    )


class InternalDomainsDetector:
    """Reports policy-listed hostnames appearing in the output."""

    id = "internal_domains"
    tier = "T1"
    sides = frozenset({OUTPUT})

    def warm(self) -> None:
        """Nothing to load. The domain list arrives per scan, from the policy."""

    def run(
        self,
        text: str,
        cfg: DetectorConfig,
        ctx: Context,  # noqa: ARG002 - the Detector protocol fixes this signature
    ) -> list[Finding]:
        raw = cfg.options.get("domains") or []
        if isinstance(raw, str):
            raw = [raw]

        # Folded here rather than at match time: a policy may write `Corp.Internal`,
        # and the folded text it is matched against is lowercase.
        domains = tuple(
            sorted(
                {
                    str(domain).strip().casefold()
                    for domain in raw
                    if str(domain).strip()
                }
            )
        )
        if not domains:
            return [
                Finding(
                    detector_id=self.id,
                    tier=self.tier,
                    label="domains_not_configured",
                    score=1.0,
                    span=None,
                    # Always log, for the reason banned_terms gives: an empty list is a
                    # gap in the policy rather than a finding about the text.
                    action="log",
                )
            ]

        pattern = compile_domains(domains)
        if pattern is None:  # pragma: no cover - unreachable, domains is non-empty
            return []

        haystack = fold(text)
        return [
            Finding(
                detector_id=self.id,
                tier=self.tier,
                label=LABEL,
                # 1.0. The domain is in the policy's list or it is not.
                score=1.0,
                span=haystack.span(match.start(), match.end()),
                action=cfg.on_fail,
            )
            for match in pattern.finditer(haystack.text)
        ]
