# SPDX-License-Identifier: Apache-2.0
"""A source-compatible shim for the archived llm-guard scanner API.

Exists so that migrating is an import change rather than a rewrite. `scan_prompt` and
`scan_output` keep llm-guard's signatures and its tuple return shape, and scanner names
map onto detector ids where a real equivalent exists.

**A scanner with no equivalent raises.** This is the whole design of the file. A shim
that
accepted `BanCode` and quietly did nothing would leave a caller believing code was being
blocked, and they would have no way to find out except by being breached. An exception
on
the first call is loud, immediate, and fixable. So the mapping below is exhaustive:
every
scanner llm-guard shipped is either mapped or listed as unsupported by name, and
`docs/migrating-from-llm-guard.md` carries the same table for people who would rather
read
than run.

One behavioural difference worth stating, because it cannot be shimmed away. llm-guard
returns a per-scanner dict of scores and a sanitised string. This library returns a
Decision carrying an evidence record, and the record is the point of it. The tuple is
reconstructed for compatibility, and `decision_for` hands back the real object for
anyone
ready to use it.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, Final

from flowx_border.detectors.catalogue import CATALOGUE

if TYPE_CHECKING:
    from flowx_border.policy import Policy
    from flowx_border.types import Decision

#: llm-guard scanner name to detector id. Only where the equivalence is real: a mapping
#  that is approximately right is worse than an absent one, because it reports a check
# the
#: caller did not ask for and did not get.
SUPPORTED: Final[dict[str, str]] = {
    # Input scanners.
    "Anonymize": "pii",
    "PromptInjection": "injection",
    "Secrets": "secrets",
    "Gibberish": "gibberish",
    "Toxicity": "toxicity",
    "BanTopics": "topic_scope",
    "NSFW": "nsfw",
    # Output scanners.
    "Deanonymize": "output_leakage",
    "Sensitive": "output_leakage",
    "NoRefusal": "politeness",
    "Bias": "bias",
    "FactualConsistency": "groundedness",
    "Relevance": "topic_scope",
}

#  Scanners with no equivalent here, and why. Listed rather than omitted so that the
# error
#: can say what the gap is instead of only that there is one.
UNSUPPORTED: Final[dict[str, str]] = {
    "BanCode": "no code detector. Out of scope for v1; the detector set is fixed.",
    "BanCompetitors": (
        "a competitor wordlist is customer-specific data, not a model. Express it as a "
        "policy over topic_scope, or keep it in your own code."
    ),
    "BanSubstrings": (
        "a substring list belongs in your code, not behind a model download."
    ),
    "Code": "no code detector, as above.",
    "InvisibleText": (
        "no zero-width or bidi-control detector yet. This is a real gap rather than a "
        "rejected idea: it is cheap and rule-based, and it would be a T0 addition."
    ),
    "Language": (
        "no language identification detector. The library supports 26 languages in "
        "every detector rather than gating on which one a text is in."
    ),
    "LanguageSame": "no language identification, as above.",
    "Regex": "a regex list belongs in your code, not behind a model download.",
    "TokenLimit": "token counting is the caller's concern, not a security check.",
    "Sentiment": (
        "no sentiment detector. politeness is the nearest, and it is not the same."
    ),
    "ReadingTime": "not a security check.",
    "MaliciousURLs": (
        "no URL reputation detector. It would need a network call at scan time, which "
        "constraint 1 rules out."
    ),
    "URLReachability": (
        "reachability is a network call at scan time, which constraint 1 rules out."
    ),
    "JSON": (
        "output shape validation is not a security check and is better done by your "
        "own schema."
    ),
}


class UnsupportedScannerError(NotImplementedError):
    """A scanner this shim will not pretend to implement."""


def _detector_ids(scanners: Sequence[Any] | None) -> list[str]:
    """Map a caller's scanner list onto detector ids. Raises on anything unsupported."""
    names = []
    for scanner in scanners or []:
        # Accept a class, an instance, or a bare string, because llm-guard callers have
        # all three shapes in the wild.
        name = getattr(scanner, "__name__", None) or type(scanner).__name__
        if isinstance(scanner, str):
            name = scanner
        names.append(name)

    unsupported = [name for name in names if name not in SUPPORTED]
    if unsupported:
        details = "\n".join(
            f"  {name}: {UNSUPPORTED.get(name, 'not a known llm-guard scanner.')}"
            for name in unsupported
        )
        raise UnsupportedScannerError(
            f"these scanners have no equivalent in flowx-border:\n{details}\n"
            "They raise rather than passing, because a security shim that silently "
            "does nothing is worse than one that fails. See "
            "docs/migrating-from-llm-guard.md."
        )
    return [SUPPORTED[name] for name in names]


def _to_tuple(
    decision: Decision, wanted: list[str]
) -> tuple[str, dict[str, bool], dict[str, float]]:
    """llm-guard's (sanitised_text, results_valid, results_score) shape.

    `results_valid` is False for a detector that found something, matching llm-guard's
    sense of valid. Scores are the highest a detector reported, since llm-guard carried
    one
    number per scanner and this library carries one per finding.
    """
    worst: dict[str, float] = dict.fromkeys(wanted, 0.0)
    for finding in decision.findings:
        if finding.detector_id in worst:
            worst[finding.detector_id] = max(worst[finding.detector_id], finding.score)
    valid = {detector: score == 0.0 for detector, score in worst.items()}
    return decision.text, valid, worst


def scan_prompt(
    prompt: str, scanners: Sequence[Any] | None = None, policy: Policy | None = None
) -> tuple[str, dict[str, bool], dict[str, float]]:
    """llm-guard's scan_prompt, backed by scan_input.

    `policy` is an addition rather than a rename: llm-guard configured behaviour by
    constructing scanners, and here behaviour is policy, which is data. Without one, the
    scanners you pass are enabled at their defaults and everything else is disabled.
    """
    from flowx_border import scan_input

    wanted = _detector_ids(scanners)
    decision = scan_input(prompt, policy or _policy_for(wanted))
    return _to_tuple(decision, wanted)


def scan_output(
    prompt: str,
    output: str,
    scanners: Sequence[Any] | None = None,
    policy: Policy | None = None,
) -> tuple[str, dict[str, bool], dict[str, float]]:
    """llm-guard's scan_output, backed by scan_output.

    The prompt is not ignored: it becomes `Context.sources`, which is what lets
    output_leakage tell a leak from the assistant repeating back what the user typed.
    llm-guard's Deanonymize and Sensitive both map here, and both are better for it.
    """
    from flowx_border import scan_output as _scan
    from flowx_border.detectors.base import Context

    wanted = _detector_ids(scanners)
    decision = _scan(output, policy or _policy_for(wanted), Context(sources=(prompt,)))
    return _to_tuple(decision, wanted)


def decision_for(
    text: str,
    side: str,
    scanners: Sequence[Any] | None = None,
    policy: Policy | None = None,
) -> Decision:
    """The real Decision, for a caller who has finished migrating.

    Here so that the tuple above is a stepping stone rather than a ceiling: the evidence
    record is the reason to be here, and llm-guard's shape has nowhere to put it.
    """
    from flowx_border import scan_input
    from flowx_border import scan_output as _scan

    wanted = _detector_ids(scanners)
    resolved = policy or _policy_for(wanted)
    return scan_input(text, resolved) if side == "input" else _scan(text, resolved)


def _policy_for(detector_ids: list[str]) -> Policy:
    """A policy enabling exactly the requested detectors, everything else off.

    T0 cannot be disabled, so `secrets` and `disclosure` are present whether or not the
    caller asked. They report rather than enforce here, because a migration should not
    start blocking traffic that llm-guard was letting through.
    """
    from flowx_border.policy import DetectorPolicy, Policy

    wanted = set(detector_ids)
    return Policy(
        policy_id="llm-guard-compat",
        version=1,
        fail_mode=dict.fromkeys(("T0", "T1", "T2", "T3"), "open"),
        detectors={
            detector: DetectorPolicy(
                enabled=detector in wanted or spec.tier == "T0",
                on_fail="flag",
            )
            for detector, spec in CATALOGUE.items()
        },
    )
