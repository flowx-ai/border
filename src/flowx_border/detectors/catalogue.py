# SPDX-License-Identifier: Apache-2.0
"""The detector catalogue: which detectors exist, their tier, and which side they read.

Data, not implementations. The engine needs to know a detector's tier and side to order
and filter it, and the policy loader needs to know which ids are real so an unknown one
is an error rather than a silently ignored typo. A policy that says `pii_detector:` when
it means `pii:` would otherwise disable PII checking and report success.

Seventeen entries as of 2026-08-11. Eight originally, thirteen on 2026-08-10 when the
Guardrails Hub classifiers were added, and four more when the cap on the detector set
was lifted and the rule-based validators from that hub were ported. See constraint 3 in
CLAUDE.md for the tradeoff each of those steps made, which the lifting overruled rather
than refuted.

The five added on 2026-08-11 are all rules, which is why they cost 5 ms rather than 75:
`banned_terms`, `system_prompt_leakage`, `markup_injection`, `internal_domains` and
`output_format`. docs/porting-guardrails-validators.md records where each came from.

Packages, and why `requires` is a field rather than a paragraph
---------------------------------------------------------------

A detector can need things the machine may not have: a network round trip, an
accelerator, a generative model, a dependency outside the base install. Which ones it
needs is a fact about the detector, so it is declared on `Spec` and `requirements_for`
reads it back.

`CORE` is every detector that needs none of them. It runs on a laptop with the interface
down, and it is what a caller gets unless they enable something else deliberately. The
point of declaring the rest is that a caller enabling one gets told at policy load,
which is when they can still change their mind, rather than finding out from a latency
graph. Nothing here refuses: `registry.deployment_notes` returns the lines and the
caller decides.
"""

from __future__ import annotations

from collections.abc import Iterable
from types import MappingProxyType
from typing import Final, NamedTuple

from flowx_border.types import Tier

INPUT: Final = "input"
OUTPUT: Final = "output"


class Spec(NamedTuple):
    tier: Tier
    sides: frozenset[str]
    # The p95 ceiling from CLAUDE.md's table, at the reference input named there
    # and in tests/test_budgets.py: 87 tokens, one thread, CPU, INT8. A budget with no
    # input
    # length attached is not a budget, which is why that reference is named everywhere
    # this number appears.
    #
    # Every encoder-backed detector carries the same 75 ms, because each is the same
    # XLM-RoBERTa base and costs the same at the same length. The T1/T2 split
    # decides when a detector runs and whether a policy may switch it off, not what it
    # costs. Measured 2026-08-11: pii 51 ms, output_leakage 51 ms, 0.60 ms per token.
    budget_ms: float

    # What this detector needs from the machine it runs on, beyond a CPU and the base
    # install. Empty for everything in CORE, which is the package that runs anywhere.
    #
    # Declared here rather than argued in a document, because it is the caller's
    # deployment question and they should get it from the library at the moment they
    # enable the detector, not from a paragraph they may not have read.
    requires: frozenset[str] = frozenset()


CATALOGUE: Final[MappingProxyType[str, Spec]] = MappingProxyType(
    {
        "secrets": Spec("T0", frozenset({INPUT}), 1.0),
        "disclosure": Spec("T0", frozenset({OUTPUT}), 5.0),
        # T0 because all 26 supported languages are left to right, so a bidi
        # override has no typographic purpose in any text this library claims to
        # support, and tag characters render nowhere at all. The categories that do
        # have legitimate uses are off by default rather than making the detector
        # optional. See its module docstring.
        "invisible_text": Spec("T0", frozenset({INPUT, OUTPUT}), 5.0),
        "pii": Spec("T1", frozenset({INPUT, OUTPUT}), 75.0),
        "output_leakage": Spec("T1", frozenset({OUTPUT}), 75.0),
        "gibberish": Spec("T1", frozenset({INPUT}), 75.0),
        # Ported from the Guardrails Hub, 2026-08-11. Rules rather than models, so they
        # sit at T1 with a rule-sized budget. T1 rather than T0 because each can be
        # wrong in a way a deployment has to be able to switch off: banned_terms and
        # internal_domains need a list only the deployer has, and markup_injection
        # fires on a coding assistant doing its job.
        "banned_terms": Spec("T1", frozenset({INPUT, OUTPUT}), 5.0),
        "system_prompt_leakage": Spec("T1", frozenset({OUTPUT}), 5.0),
        "markup_injection": Spec("T1", frozenset({INPUT, OUTPUT}), 5.0),
        "internal_domains": Spec("T1", frozenset({OUTPUT}), 5.0),
        # Shape rather than security, and the only entry here that is. It exists so
        # that sixteen hub shape validators have one destination instead of sixteen.
        "output_format": Spec("T1", frozenset({OUTPUT}), 5.0),
        # The first entry to leave CORE. It needs the sqlglot parser, which is the
        # `sql` extra rather than a base dependency, because only a text-to-SQL
        # product wants it and nobody else should pay the install weight.
        "sql_injection": Spec(
            "T1", frozenset({OUTPUT}), 5.0, frozenset({"dependency"})
        ),
        "injection": Spec("T2", frozenset({INPUT}), 75.0),
        "regulated_advice": Spec("T2", frozenset({OUTPUT}), 75.0),
        "toxicity": Spec("T2", frozenset({INPUT, OUTPUT}), 75.0),
        "nsfw": Spec("T2", frozenset({INPUT, OUTPUT}), 75.0),
        "bias": Spec("T2", frozenset({OUTPUT}), 75.0),
        "politeness": Spec("T2", frozenset({OUTPUT}), 75.0),
        # The only detector that leaves the machine, and the only one whose budget
        # is a deadline it enforces on itself rather than a figure somebody
        # measured: it depends on a network the library does not control.
        "url_reachability": Spec(
            "T3", frozenset({OUTPUT}), 3000.0, frozenset({"network"})
        ),
        "topic_scope": Spec("T3", frozenset({INPUT}), 300.0),
        "groundedness": Spec("T3", frozenset({OUTPUT}), 300.0),
    }
)

#: What a requirement means for whoever is deploying this. One line each, because
#: these are shown to a caller who selected a detector rather than read a document.
REQUIREMENTS: Final[MappingProxyType[str, str]] = MappingProxyType(
    {
        "network": (
            "reaches another machine during a scan, so a third party is in the latency "
            "path of every request and their outage becomes yours"
        ),
        "gpu": "needs an accelerator to meet its budget; CPU will be far slower",
        "llm": (
            "runs a generative model, so its verdict is only reproducible with "
            "decoding "
            "pinned, and an evidence record depends on that"
        ),
        "dependency": "needs a runtime dependency outside the base install",
    }
)

#: The detectors that need nothing beyond a CPU and the base install. This is the
#: package that runs on a laptop with the network interface down, and it is what a
#: caller gets unless they deliberately enable something else.
CORE: Final[frozenset[str]] = frozenset(
    detector for detector, spec in CATALOGUE.items() if not spec.requires
)


def requirements_for(detector_ids: Iterable[str]) -> dict[str, tuple[str, ...]]:
    """Requirement to the detectors that bring it in, for a set of detector ids.

    Empty when everything asked for is in CORE, which is the common case and the one
    that should stay silent. A caller renders this at the moment a policy is loaded, so
    enabling a detector that needs a GPU is something they are told rather than
    something they discover in production.
    """
    out: dict[str, list[str]] = {}
    for detector_id in sorted(set(detector_ids)):
        spec = CATALOGUE.get(detector_id)
        if spec is None:
            continue
        for requirement in sorted(spec.requires):
            out.setdefault(requirement, []).append(detector_id)
    return {requirement: tuple(names) for requirement, names in sorted(out.items())}


TIER_ORDER: Final[tuple[Tier, ...]] = ("T0", "T1", "T2", "T3")

# T0 always runs and cannot be disabled. The policy loader rejects an attempt to
# disable one rather than quietly honouring it.
ALWAYS_ON: Final[frozenset[str]] = frozenset(
    detector for detector, spec in CATALOGUE.items() if spec.tier == "T0"
)


def ids_for(side: str, tier: Tier) -> tuple[str, ...]:
    """Detector ids that read this side at this tier, in a stable order.

    Stable because the evidence record lists the detectors that ran, and a record whose
    detector order depends on dict iteration would hash differently across runs for the
    same scan. Determinism is constraint 6.
    """
    return tuple(
        sorted(
            detector
            for detector, spec in CATALOGUE.items()
            if spec.tier == tier and side in spec.sides
        )
    )
