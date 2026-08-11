# SPDX-License-Identifier: Apache-2.0
"""The detector catalogue: which detectors exist, their tier, and which side they read.

Data, not implementations. The engine needs to know a detector's tier and side to order
and filter it, and the policy loader needs to know which ids are real so an unknown one
is an error rather than a silently ignored typo. A policy that says `pii_detector:` when
it means `pii:` would otherwise disable PII checking and report success.

Thirteen entries as of 2026-08-10, when the set was extended past the original eight on
explicit instruction. See constraint 3 in CLAUDE.md for what that traded away.
"""

from __future__ import annotations

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


CATALOGUE: Final[MappingProxyType[str, Spec]] = MappingProxyType(
    {
        "secrets": Spec("T0", frozenset({INPUT}), 1.0),
        "disclosure": Spec("T0", frozenset({OUTPUT}), 5.0),
        "pii": Spec("T1", frozenset({INPUT, OUTPUT}), 75.0),
        "output_leakage": Spec("T1", frozenset({OUTPUT}), 75.0),
        "gibberish": Spec("T1", frozenset({INPUT}), 75.0),
        "injection": Spec("T2", frozenset({INPUT}), 75.0),
        "regulated_advice": Spec("T2", frozenset({OUTPUT}), 75.0),
        "toxicity": Spec("T2", frozenset({INPUT, OUTPUT}), 75.0),
        "nsfw": Spec("T2", frozenset({INPUT, OUTPUT}), 75.0),
        "bias": Spec("T2", frozenset({OUTPUT}), 75.0),
        "politeness": Spec("T2", frozenset({OUTPUT}), 75.0),
        "topic_scope": Spec("T3", frozenset({INPUT}), 300.0),
        "groundedness": Spec("T3", frozenset({OUTPUT}), 300.0),
    }
)

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
