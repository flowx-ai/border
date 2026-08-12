# SPDX-License-Identifier: Apache-2.0
"""A source-compatible shim for the archived llm-guard scanner API.

Exists so that migrating is an import change rather than a rewrite. `scan_prompt` and
`scan_output` keep llm-guard's signatures and its tuple return shape, and scanner names
map onto detector ids where a real equivalent exists.

**A scanner with no equivalent raises.** This is the whole design of the file. A shim
that accepted `BanCode` and quietly did nothing would leave a caller believing code was
being blocked, and they would have no way to find out except by being breached. An
exception on the first call is loud, immediate, and fixable. So the mapping below is
exhaustive:
every scanner llm-guard shipped is either mapped or listed as unsupported by name, and
`docs/migrating-from-llm-guard.md` carries the same table for people who would rather
read than run.

One behavioural difference worth stating, because it cannot be shimmed away. llm-guard
returns a per-scanner dict of scores and a sanitised string. This library returns a
Decision carrying an evidence record, and the record is the point of it. The tuple is
reconstructed for compatibility, and `decision_for` hands back the real object for
anyone ready to use it.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, Final

from flowx_border.detectors.catalogue import CATALOGUE

if TYPE_CHECKING:
    from flowx_border.policy import Policy
    from flowx_border.types import Decision

#: llm-guard scanner name to detector id. Only where the equivalence is real: a mapping
# that is approximately right is worse than an absent one, because it reports a check
# the
#: caller did not ask for and did not get.
SUPPORTED: Final[dict[str, str]] = {
    # Input scanners.
    "Anonymize": "pii",
    # Listed as unsupported until 2026-08-12, with a note saying no detector reported
    # these characters yet. One had shipped: invisible_text is T0, in CORE, and covers
    # bidirectional controls, tag characters and zero-width characters. A migration
    # table that understates what exists sends people away for a capability they already
    # have.
    "InvisibleText": "invisible_text",
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
    # Added 2026-08-11 with the Guardrails Hub port. Each of these was in UNSUPPORTED
    # until the detector it names existed, and the note there said so. See
    # docs/porting-guardrails-validators.md.
    "BanSubstrings": "banned_terms",
    "BanCompetitors": "banned_terms",
    "JSON": "output_format",
    "Regex": "output_format",
    "ReadingTime": "output_format",
    "URLReachability": "url_reachability",
}

#: Scanners that map onto a detector whose entire input is data the caller has to
#: supply. llm-guard took that data as constructor arguments, `BanSubstrings(substrings=
#: [...])`; here it is policy, and this shim cannot invent it.
#: Passing one of these without a `policy=` raises. That is the same rule the file
#: already applies to an unmapped scanner, for the same reason: `banned_terms` with no
#: terms reports `terms_not_configured` and finds nothing, so accepting the call would
#: hand back a clean-looking result for a check that never ran. The error names the
#: option to set, so the fix is in the message.
NEEDS_POLICY: Final[dict[str, str]] = {
    "BanSubstrings": "banned_terms.options.terms, with whole_words: false",
    "BanCompetitors": "banned_terms.options.terms",
    "Regex": "output_format.options.regex",
    "ReadingTime": "output_format.options.max_reading_seconds",
    "JSON": "output_format.options.json: true",
}

# Scanners with no equivalent here, and why. Listed rather than omitted so that the
# error
#: can say what the gap is instead of only that there is one.
UNSUPPORTED: Final[dict[str, str]] = {
    "BanCode": (
        "no code detector. sql_injection parses generated SQL and says nothing about "
        "code in any other language, or about whether prose contains a code block."
    ),
    "Code": "no code detector, as above.",
    "Language": (
        "no language identification detector. The library supports 26 languages in "
        "every detector rather than gating on which one a text is in."
    ),
    "LanguageSame": "no language identification, as above.",
    "TokenLimit": (
        "output_format counts graphemes and words, and a token limit is neither. "
        "Tokens depend on the tokenizer of the model you are calling, which this "
        "library does not know, so mapping this onto max_length would report a "
        "different number than the one you asked about."
    ),
    "Sentiment": (
        "no sentiment detector. politeness is the nearest, and it is not the same."
    ),
    "MaliciousURLs": (
        "no URL reputation detector. url_reachability asks whether a link answers, "
        "which is a different question from whether it is hostile, and answering the "
        "second needs a reputation feed this library does not ship."
    ),
}


class UnsupportedScannerError(NotImplementedError):
    """A scanner this shim will not pretend to implement."""


class UnconfiguredScannerError(ValueError):
    """A mapped scanner whose detector needs data only a policy can supply.

    Separate from UnsupportedScannerError because it is a different problem with a
    different fix: the check exists and is wired, and what is missing is the list. Both
    raise for the same underlying reason, which is that the alternative is a call that
    returns a clean result for a check that never ran.
    """


def _scanner_names(scanners: Sequence[Any] | None) -> list[str]:
    """Scanner names from classes, instances or bare strings.

    All three shapes are in the wild: llm-guard's own examples construct instances, its
    README lists classes, and configuration files carry strings.
    """
    names = []
    for scanner in scanners or []:
        name = getattr(scanner, "__name__", None) or type(scanner).__name__
        if isinstance(scanner, str):
            name = scanner
        names.append(name)
    return names


def _detector_ids(scanners: Sequence[Any] | None) -> list[str]:
    """Map a caller's scanner list onto detector ids. Raises on anything unsupported."""
    names = _scanner_names(scanners)

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
    one number per scanner and this library carries one per finding.
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

    _require_policy_for(_scanner_names(scanners), policy)
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

    _require_policy_for(_scanner_names(scanners), policy)
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

    _require_policy_for(_scanner_names(scanners), policy)
    wanted = _detector_ids(scanners)
    resolved = policy or _policy_for(wanted)
    return scan_input(text, resolved) if side == "input" else _scan(text, resolved)


def _require_policy_for(names: list[str], policy: Policy | None) -> None:
    """Refuse a scanner that needs configuration when no policy carries it.

    llm-guard configured a scan by how you constructed the scanner:
    `BanSubstrings(substrings=[...])`. Here configuration is policy, which is data, and
    this shim has nowhere to read a constructor argument from even when the caller
    passes an instance, because the attribute names are private to that library and
    guessing them wrong produces an empty list rather than an error.

    An empty list is the case that matters. `banned_terms` with no terms reports
    `terms_not_configured` and finds nothing, so accepting the call would return a
    clean-looking tuple for a check that never ran. That is the exact failure this
    shim's unsupported table exists to prevent, so it gets the same treatment.
    """
    if policy is not None:
        return
    unconfigured = [name for name in names if name in NEEDS_POLICY]
    if not unconfigured:
        return
    details = "\n".join(f"  {name}: set {NEEDS_POLICY[name]}" for name in unconfigured)
    raise UnconfiguredScannerError(
        f"these scanners need configuration that only a policy can carry:\n{details}\n"
        "llm-guard took it as constructor arguments; here it is policy, because a "
        "policy is data a reviewer can read and its hash pins what ran. Pass policy= "
        "with those options set. This raises rather than scanning, because the "
        "detector would report that it was unconfigured and the tuple would look "
        "clean. See docs/migrating-from-llm-guard.md."
    )


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
