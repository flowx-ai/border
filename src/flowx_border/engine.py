# SPDX-License-Identifier: Apache-2.0
"""Tier orchestration.

Four things here are easy to get subtly wrong, so each is called out where it happens:

1. **Tier order and escalation.** T0, T1, T2 always run. T3 runs only when a lower tier
   produced a finding at or above its threshold, or when the policy sets `always: true`
   for that detector. T3 is the 300 ms tier, so running it unconditionally would make
   every scan cost what the worst scan costs.

2. **Short circuit on block.** The moment any finding carries action `block`, later
   tiers do not run. The text is already refused; spending 300 ms to describe it more
   precisely is waste.

3. **Redaction applies spans right to left.** Replacing left to right invalidates every
   later offset, which silently corrupts the output. This is the single most likely bug
   in the file and the reason `_redact` sorts descending.

4. **fail_mode decides what a detector exception means.** Closed means the scan blocks:
   an unavailable check is treated as a failed check. Open means the exception is
   recorded as a finding with action `log` and the scan continues. Neither swallows it.

There is no branch on a particular detector id anywhere in this file. If a change seems
to need one, the Detector protocol is wrong and that is the thing to fix.
"""

from __future__ import annotations

import time
from collections.abc import Iterable, Mapping, Sequence

from flowx_border.detectors.base import Context, Detector
from flowx_border.detectors.catalogue import CATALOGUE, TIER_ORDER
from flowx_border.evidence import build_record
from flowx_border.policy import Policy
from flowx_border.types import Decision, Finding, Tier, Verdict

# Which verdict a set of actions implies, most severe first. `rewrite` and `redact` both
# mean the text changed, so they share a verdict: a caller needs to know the text is not
# what came in, and the finding says which detector changed it and how.
_ACTION_VERDICT: tuple[tuple[str, Verdict], ...] = (
    ("block", "block"),
    ("redact", "redact"),
    ("rewrite", "redact"),
    ("flag", "flag"),
)


def _verdict_for(findings: Sequence[Finding]) -> Verdict:
    actions = {finding.action for finding in findings}
    for action, verdict in _ACTION_VERDICT:
        if action in actions:
            return verdict
    # Findings that only ask to be logged do not change the verdict. A scan that
    # recorded something for the audit trail still allowed the text.
    return "allow"


def _redact(text: str, findings: Iterable[Finding]) -> str:
    """Replace spans with typed placeholders, right to left.

    Right to left is not a style choice. Each replacement changes the length of the
    string, so applying them left to right shifts every subsequent span by the delta and
    corrupts the result. Sorting by start descending means every span is applied while
    its own offsets are still valid.

    Overlapping spans are resolved by taking the widest at each position and dropping
    spans contained within one already applied. Two detectors finding the same IBAN, one
    with a slightly wider span, must not produce a doubly-substituted string.
    """
    spans: list[tuple[int, int, str]] = sorted(
        (
            (finding.span[0], finding.span[1], finding.label)
            for finding in findings
            if finding.span is not None and finding.action in ("redact", "rewrite")
        ),
        key=lambda item: (item[0], -(item[1] - item[0])),
    )
    if not spans:
        return text

    # Merge overlaps first, keeping the outermost extent, so a nested span cannot be
    # substituted into text that a wider span already replaced.
    merged: list[tuple[int, int, str]] = []
    for start, end, label in spans:
        if merged and start < merged[-1][1]:
            previous_start, previous_end, previous_label = merged[-1]
            if end > previous_end:
                merged[-1] = (previous_start, end, previous_label)
            continue
        merged.append((start, end, label))

    out = text
    for start, end, label in reversed(merged):
        out = f"{out[:start]}[{label.upper()}]{out[end:]}"
    return out


def _should_escalate(findings: Sequence[Finding], policy: Policy) -> bool:
    """True when some finding met its detector's threshold.

    Compared against the threshold rather than just existing: a detector may report a
    low-confidence finding, and escalating the expensive tier on a 0.1 score would make
    T3 run on nearly every scan.
    """
    for finding in findings:
        if finding.action == "log":
            continue
        if finding.score >= policy.for_detector(finding.detector_id).threshold:
            return True
    return False


def run_scan(
    text: str,
    side: str,
    policy: Policy,
    ctx: Context | None,
    detectors: Mapping[str, Detector],
) -> Decision:
    """Run the tiers for one side and build a Decision plus its evidence record.

    `detectors` is injected rather than discovered so that the engine is testable with
    fakes and so that a caller can supply a subset. A policy naming a detector that is
    not in the mapping is not an error here: the policy describes intent, the mapping
    describes what is loaded, and a detector that ships unavailable is absent by design.
    """
    context = ctx if ctx is not None else Context()
    findings: list[Finding] = []
    tiers_run: list[Tier] = []
    started = time.perf_counter()
    blocked = False

    for tier in TIER_ORDER:
        if blocked:
            break

        candidates = [
            (detector_id, detectors[detector_id])
            for detector_id in sorted(detectors)
            if detector_id in CATALOGUE
            and CATALOGUE[detector_id].tier == tier
            and side in CATALOGUE[detector_id].sides
            and policy.enabled_for(detector_id)
        ]
        if not candidates:
            continue

        if tier == "T3":
            escalated = _should_escalate(findings, policy)
            candidates = [
                (detector_id, detector)
                for detector_id, detector in candidates
                if escalated or policy.for_detector(detector_id).always
            ]
            if not candidates:
                continue

        tiers_run.append(tier)
        fail_closed = policy.fail_mode[tier] == "closed"

        for detector_id, detector in candidates:
            entry = policy.for_detector(detector_id)
            try:
                produced = detector.run(text, entry.to_detector_config(), context)
            except Exception:
                # Never re-raise into the caller's request path, and never swallow it.
                # fail_mode decides which.
                findings.append(
                    Finding(
                        detector_id=detector_id,
                        tier=tier,
                        label="detector_error",
                        score=1.0,
                        action="block" if fail_closed else "log",
                        span=None,
                    )
                )
                if fail_closed:
                    blocked = True
                    break
                continue

            for finding in produced:
                findings.append(finding)
                if finding.action == "block":
                    blocked = True

            if blocked:
                break

    elapsed_ms = (time.perf_counter() - started) * 1000.0
    verdict = _verdict_for(findings)
    # A blocked scan returns the original text. Redacting text nobody will use would
    # spend work to produce something the caller must discard anyway.
    out_text = text if verdict == "block" else _redact(text, findings)

    record = build_record(
        direction=side,  # type: ignore[arg-type]
        policy=policy,
        original_text=text,
        verdict=verdict,
        findings=findings,
        detectors={
            detector_id: detectors[detector_id] for detector_id in sorted(detectors)
        },
    )

    return Decision(
        verdict=verdict,
        text=out_text,
        original_text=text,
        findings=findings,
        evidence=record,
        elapsed_ms=elapsed_ms,
        tiers_run=tiers_run,
    )
