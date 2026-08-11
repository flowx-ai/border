# SPDX-License-Identifier: Apache-2.0
"""Tests for tier orchestration.

Fake in-memory detectors throughout. No real detector exists yet, and that is the point
of testing the engine first: the tier logic, the short circuit, the fail modes and the
redaction arithmetic get pinned down with nothing slow or stochastic in the way.

The four properties worth the most here, in order of how badly a bug would hurt:

1. **Redaction offsets.** A left-to-right implementation silently corrupts output. The
   tests below use placeholders of a different length from the text they replace, so a
   regression produces a visibly wrong string rather than a subtly wrong one.
2. **Short circuit.** Asserted by counting calls on the fakes, not by inspecting the
   verdict. A verdict can be right while the engine did three times the work.
3. **Fail modes.** A detector that raises must not raise into the caller, and must not
   vanish either. Both halves are tested.
4. **Escalation.** T3 is the 300 ms tier. A bug that runs it unconditionally does not
   fail any correctness test, only the latency budget, so it is tested here directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.engine import run_scan
from flowx_border.policy import DetectorPolicy, FailMode, Policy
from flowx_border.types import Action, Decision, Finding, Tier

# --------------------------------------------------------------------------- fakes


@dataclass
class Fake:
    """A detector that returns what it was told to return, and counts its calls.

    `tier` and `sides` are declared because the protocol requires them, but the engine
    reads the catalogue instead. `test_the_catalogue_decides_the_tier_not_the_detector`
    pins that down: a detector must not be able to promote itself into T0.
    """

    id: str
    tier: str = "T0"
    sides: frozenset[str] = field(
        default_factory=lambda: frozenset({"input", "output"})
    )
    findings: tuple[Finding, ...] = ()
    raises: bool = False
    calls: int = 0
    warmed: int = 0
    seen_text: str | None = None
    seen_config: DetectorConfig | None = None
    seen_context: Context | None = None

    def warm(self) -> None:
        self.warmed += 1

    def run(self, text: str, cfg: DetectorConfig, ctx: Context) -> list[Finding]:
        self.calls += 1
        self.seen_text = text
        self.seen_config = cfg
        self.seen_context = ctx
        if self.raises:
            raise RuntimeError("the model file is not there")
        return list(self.findings)


def finding(
    detector_id: str,
    tier: Tier,
    action: Action,
    *,
    label: str = "thing",
    score: float = 0.9,
    span: tuple[int, int] | None = None,
) -> Finding:
    return Finding(
        detector_id=detector_id,
        tier=tier,
        label=label,
        score=score,
        span=span,
        action=action,
    )


def detector(
    detector_id: str,
    tier: Tier,
    action: Action | None = None,
    *,
    score: float = 0.9,
    label: str = "thing",
    span: tuple[int, int] | None = None,
    raises: bool = False,
) -> Fake:
    """A fake that produces one finding, or none when `action` is None."""
    produced = (
        ()
        if action is None
        else (finding(detector_id, tier, action, label=label, score=score, span=span),)
    )
    return Fake(id=detector_id, tier=tier, findings=produced, raises=raises)


def policy(
    *,
    fail_mode: FailMode | dict[Tier, FailMode] = "open",
    **detectors: DetectorPolicy,
) -> Policy:
    """A policy built in memory. The YAML path is covered in test_policy.py."""
    modes: dict[Tier, FailMode] = (
        dict.fromkeys(("T0", "T1", "T2", "T3"), fail_mode)
        if isinstance(fail_mode, str)
        else fail_mode
    )
    return Policy(policy_id="test", version=1, fail_mode=modes, detectors=detectors)


def scan(
    text: str,
    *fakes: Fake,
    side: str = "input",
    pol: Policy | None = None,
    ctx: Context | None = None,
) -> Decision:
    return run_scan(
        text,
        side,
        pol if pol is not None else policy(),
        ctx,
        {fake.id: fake for fake in fakes},
    )


# --------------------------------------------------------------------------- tier order


def test_tiers_run_in_ascending_order() -> None:
    decision = scan(
        "hello",
        detector("secrets", "T0"),
        detector("pii", "T1"),
        detector("injection", "T2"),
    )
    assert decision.tiers_run == ["T0", "T1", "T2"]


def test_a_tier_with_no_detector_is_not_recorded_as_run() -> None:
    # tiers_run is an audit claim. Listing a tier that had nothing to do would overstate
    # what the scan checked.
    decision = scan("hello", detector("secrets", "T0"))
    assert decision.tiers_run == ["T0"]


def test_the_catalogue_decides_the_tier_not_the_detector() -> None:
    # `injection` is T2 in the catalogue. A fake that calls itself T0 still runs as T2,
    # so a detector cannot promote itself into the tier that always runs.
    late = Fake(id="injection", tier="T0")
    decision = scan("hello", late)
    assert decision.tiers_run == ["T2"]


def test_a_detector_for_the_other_side_does_not_run() -> None:
    output_only = detector("disclosure", "T0", "flag")
    decision = scan("hello", output_only, side="input")
    assert output_only.calls == 0
    assert decision.verdict == "allow"


def test_a_disabled_detector_does_not_run() -> None:
    off = detector("injection", "T2", "block")
    decision = scan("hello", off, pol=policy(injection=DetectorPolicy(enabled=False)))
    assert off.calls == 0
    assert decision.verdict == "allow"


def test_t0_cannot_be_disabled_by_any_route() -> None:
    # Two independent guards, because a disabled floor is the failure that would be
    # hardest to notice: the scan still returns, still produces a record, and checks
    # less. Guard one: a Policy carrying a disabled T0 cannot be constructed at all, in
    # code or from YAML.
    with pytest.raises(Exception, match="cannot be disabled"):
        policy(secrets=DetectorPolicy(enabled=False))

    # Guard two: the engine asks `enabled_for`, which answers True for T0 whatever the
    # policy says, so the engine does not depend on guard one having held.
    assert policy().enabled_for("secrets") is True
    always = detector("secrets", "T0", "flag")
    scan("hello", always)
    assert always.calls == 1


# --------------------------------------------------------------------------- escalation


def test_t3_does_not_run_when_nothing_flagged() -> None:
    expensive = detector("topic_scope", "T3", "flag")
    decision = scan("hello", detector("secrets", "T0"), expensive)
    assert expensive.calls == 0
    assert "T3" not in decision.tiers_run


def test_t3_runs_when_a_lower_tier_met_its_threshold() -> None:
    expensive = detector("topic_scope", "T3", "flag")
    decision = scan("hello", detector("pii", "T1", "flag", score=0.9), expensive)
    assert expensive.calls == 1
    assert decision.tiers_run == ["T1", "T3"]


def test_a_finding_below_its_threshold_does_not_escalate() -> None:
    # Without the threshold comparison a 0.1 score would pull in the 300 ms tier, and T3
    # would effectively run on every scan.
    expensive = detector("topic_scope", "T3", "flag")
    scan(
        "hello",
        detector("pii", "T1", "flag", score=0.2),
        expensive,
        pol=policy(pii=DetectorPolicy(threshold=0.8)),
    )
    assert expensive.calls == 0


def test_a_log_only_finding_does_not_escalate() -> None:
    # `log` means "write it down", not "look harder".
    expensive = detector("topic_scope", "T3", "flag")
    scan("hello", detector("pii", "T1", "log", score=1.0), expensive)
    assert expensive.calls == 0


def test_always_true_runs_t3_with_no_escalation() -> None:
    expensive = detector("topic_scope", "T3", "flag")
    decision = scan(
        "hello",
        expensive,
        pol=policy(topic_scope=DetectorPolicy(always=True)),
    )
    assert expensive.calls == 1
    assert decision.tiers_run == ["T3"]


def test_always_is_per_detector_not_per_tier() -> None:
    # On the output side there are two T3 detectors. `always` on one must not drag the
    # other in: that would double the worst-case cost of turning one of them on.
    grounded = detector("groundedness", "T3", "flag")
    decision = scan(
        "hello",
        grounded,
        detector("regulated_advice", "T2"),
        side="output",
        pol=policy(groundedness=DetectorPolicy(always=True)),
    )
    assert grounded.calls == 1
    assert decision.tiers_run == ["T2", "T3"]


# ------------------------------------------------------------------- short circuit


def test_a_block_at_t0_stops_the_later_tiers() -> None:
    later = detector("pii", "T1", "flag")
    even_later = detector("injection", "T2", "flag")
    decision = scan("hello", detector("secrets", "T0", "block"), later, even_later)
    assert (later.calls, even_later.calls) == (0, 0)
    assert decision.tiers_run == ["T0"]
    assert decision.verdict == "block"


def test_a_block_stops_the_rest_of_its_own_tier() -> None:
    # Within-tier short circuit matters as much as between-tier: on the output side four
    # T2 detectors share a tier, and three of them are 50 ms each.
    blocker = detector("bias", "T2", "block")
    sibling = detector("politeness", "T2", "flag")
    scan("hello", blocker, sibling, side="output")
    # `bias` sorts before `politeness`, so the blocker runs first and cuts the sibling.
    assert (blocker.calls, sibling.calls) == (1, 0)


def test_detectors_run_in_a_stable_order_within_a_tier() -> None:
    # Sorted, not dict order. The evidence record lists what ran, and a record whose
    # order depended on insertion would differ between two identical scans.
    order: list[str] = []

    class Recording(Fake):
        def run(self, text: str, cfg: DetectorConfig, ctx: Context) -> list[Finding]:
            order.append(self.id)
            return super().run(text, cfg, ctx)

    scan(
        "hello",
        Recording(id="nsfw"),
        Recording(id="injection"),
        Recording(id="toxicity"),
    )
    assert order == ["injection", "nsfw", "toxicity"]


def test_a_blocked_scan_returns_the_original_text() -> None:
    # Redacting text the caller must discard anyway is work for nothing, and a
    # partly-redacted string returned on a block invites a caller to use it.
    text = "my key is AKIAIOSFODNN7EXAMPLE"
    decision = scan(
        text,
        detector("secrets", "T0", "block", label="aws_key", span=(10, 30)),
    )
    assert decision.text == text
    assert decision.original_text == text


# --------------------------------------------------------------------------- fail modes


def test_fail_open_records_the_error_and_keeps_going() -> None:
    broken = detector("pii", "T1", raises=True)
    later = detector("injection", "T2", "flag")
    decision = scan("hello", broken, later, pol=policy(fail_mode="open"))

    assert later.calls == 1
    errors = [f for f in decision.findings if f.label == "detector_error"]
    assert [f.detector_id for f in errors] == ["pii"]
    assert errors[0].action == "log"


def test_fail_open_does_not_change_the_verdict_by_itself() -> None:
    decision = scan(
        "hello", detector("pii", "T1", raises=True), pol=policy(fail_mode="open")
    )
    assert decision.verdict == "allow"


def test_fail_closed_blocks_and_stops() -> None:
    broken = detector("pii", "T1", raises=True)
    later = detector("injection", "T2", "flag")
    decision = scan("hello", broken, later, pol=policy(fail_mode="closed"))

    assert decision.verdict == "block"
    assert later.calls == 0


def test_fail_mode_is_read_per_tier() -> None:
    # The shipped bfsi policy fails closed on T0 and T1 and open above, because failing
    # closed on a 300 ms model that did not load would take the assistant down.
    modes: dict[Tier, FailMode] = {
        "T0": "closed",
        "T1": "closed",
        "T2": "open",
        "T3": "open",
    }
    decision = scan(
        "hello",
        detector("injection", "T2", raises=True),
        pol=policy(fail_mode=modes),
    )
    assert decision.verdict == "allow"

    decision = scan(
        "hello",
        detector("pii", "T1", raises=True),
        pol=policy(fail_mode=modes),
    )
    assert decision.verdict == "block"


def test_an_exception_never_reaches_the_caller() -> None:
    # A guard that takes down the request path it guards is worse than no guard.
    for mode in ("open", "closed"):
        decision = scan(
            "hello", detector("pii", "T1", raises=True), pol=policy(fail_mode=mode)
        )
        assert decision.evidence.record_id


def test_the_error_finding_names_the_detector_that_failed() -> None:
    # Otherwise the audit trail says a check did not happen without saying which.
    decision = scan(
        "hello",
        detector("pii", "T1", raises=True),
        detector("gibberish", "T1", "flag"),
        pol=policy(fail_mode="open"),
    )
    summary = {(f.detector_id, f.label) for f in decision.evidence.finding_summary}
    assert ("pii", "detector_error") in summary


def test_findings_from_before_a_closed_failure_survive() -> None:
    decision = scan(
        "hello",
        detector("secrets", "T0", "flag", label="token"),
        detector("pii", "T1", raises=True),
        pol=policy(fail_mode="closed"),
    )
    labels = [f.label for f in decision.findings]
    assert labels == ["token", "detector_error"]


# --------------------------------------------------------------------------- redaction

PHONE_TEXT = "call 0700123456 or mail bob@x.io now"


def test_a_single_span_becomes_a_typed_placeholder() -> None:
    decision = scan(
        PHONE_TEXT,
        detector("pii", "T1", "redact", label="phone", span=(5, 15)),
    )
    assert decision.text == "call [PHONE] or mail bob@x.io now"
    assert decision.verdict == "redact"


def test_two_spans_are_applied_right_to_left() -> None:
    # The regression this catches: [PHONE] is 7 characters replacing 10, so a
    # left-to-right implementation shifts the email span by 3 and mangles the output.
    decision = scan(
        PHONE_TEXT,
        detector("pii", "T1", "redact", label="phone", span=(5, 15)),
        detector("gibberish", "T1", "redact", label="email", span=(24, 32)),
    )
    assert decision.text == "call [PHONE] or mail [EMAIL] now"


def test_the_original_text_is_kept_alongside_the_redacted_text() -> None:
    decision = scan(
        PHONE_TEXT, detector("pii", "T1", "redact", label="phone", span=(5, 15))
    )
    assert decision.original_text == PHONE_TEXT
    assert decision.text != PHONE_TEXT


def test_a_span_inside_another_is_dropped() -> None:
    # Two detectors on the same IBAN, one with a wider span. Substituting the inner one
    # into text the outer already replaced would produce nested placeholders.
    inner = finding("pii", "T1", "redact", label="digits", span=(6, 10))
    outer = finding("pii", "T1", "redact", label="iban", span=(5, 15))
    decision = scan(PHONE_TEXT, Fake(id="pii", findings=(inner, outer)))
    assert decision.text == "call [IBAN] or mail bob@x.io now"


def test_partly_overlapping_spans_merge_to_the_outer_extent() -> None:
    left = finding("pii", "T1", "redact", label="a", span=(5, 12))
    right = finding("pii", "T1", "redact", label="b", span=(10, 15))
    decision = scan(PHONE_TEXT, Fake(id="pii", findings=(left, right)))
    # One placeholder covering 5..15, labelled by the span that started first.
    assert decision.text == "call [A] or mail bob@x.io now"


def test_touching_spans_are_both_applied() -> None:
    # end == next start is adjacency, not overlap. Merging them would lose a label.
    left = finding("pii", "T1", "redact", label="a", span=(5, 10))
    right = finding("pii", "T1", "redact", label="b", span=(10, 15))
    decision = scan(PHONE_TEXT, Fake(id="pii", findings=(left, right)))
    assert decision.text == "call [A][B] or mail bob@x.io now"


def test_identical_spans_from_two_detectors_are_applied_once() -> None:
    decision = scan(
        PHONE_TEXT,
        detector("pii", "T1", "redact", label="phone", span=(5, 15)),
        detector("gibberish", "T1", "redact", label="phone", span=(5, 15)),
    )
    assert decision.text == "call [PHONE] or mail bob@x.io now"


def test_a_flagged_span_is_not_redacted() -> None:
    # The action decides, not the presence of a span. A flag records where something is
    # without changing the text.
    decision = scan(
        PHONE_TEXT, detector("pii", "T1", "flag", label="phone", span=(5, 15))
    )
    assert decision.text == PHONE_TEXT
    assert decision.verdict == "flag"


def test_a_redact_action_with_no_span_leaves_the_text_alone() -> None:
    # A detector that says "redact" without saying where cannot be honoured. The verdict
    # still reports that the text was not cleared, so the caller is not misled.
    decision = scan(PHONE_TEXT, detector("pii", "T1", "redact", span=None))
    assert decision.text == PHONE_TEXT
    assert decision.verdict == "redact"


def test_a_zero_width_span_does_not_corrupt_the_text() -> None:
    decision = scan(PHONE_TEXT, detector("pii", "T1", "redact", label="x", span=(5, 5)))
    assert decision.text == "call [X]0700123456 or mail bob@x.io now"


def test_redaction_counts_characters_not_bytes() -> None:
    # Offsets are Python string indices. A detector working in UTF-8 bytes would be off
    # by one per non-ASCII character before it, so this is the test that says which.
    text = "Adresa mea: Strada Câmpului 5"
    decision = scan(
        text, detector("pii", "T1", "redact", label="address", span=(12, 29))
    )
    assert decision.text == "Adresa mea: [ADDRESS]"


# --------------------------------------------------------------------------- verdict


@pytest.mark.parametrize(
    ("actions", "expected"),
    [
        (("log",), "allow"),
        (("flag",), "flag"),
        (("redact",), "redact"),
        (("rewrite",), "redact"),
        (("block",), "block"),
        (("flag", "redact"), "redact"),
        (("redact", "block"), "block"),
        (("log", "flag"), "flag"),
    ],
)
def test_the_most_severe_action_sets_the_verdict(
    actions: tuple[Action, ...], expected: str
) -> None:
    ids = ("secrets", "pii", "injection")
    tiers: tuple[Tier, ...] = ("T0", "T1", "T2")
    fakes = [
        detector(ids[i], tiers[i], action, span=None)
        for i, action in enumerate(actions)
    ]
    assert scan("hello", *fakes).verdict == expected


def test_no_findings_means_allow_and_unchanged_text() -> None:
    decision = scan("hello", detector("secrets", "T0"))
    assert (decision.verdict, decision.text) == ("allow", "hello")
    assert decision.findings == []


def test_an_empty_detector_set_produces_a_record_and_no_tiers() -> None:
    # What an install with nothing loaded does. It must not look like a clean scan of a
    # checked text, which is why registry.assert_satisfiable exists on the layer above.
    decision = run_scan("hello", "input", policy(), None, {})
    assert (decision.verdict, decision.tiers_run) == ("allow", [])
    assert decision.evidence.detectors == ()


# --------------------------------------------------------------------------- plumbing


def test_the_detector_receives_the_resolved_policy_for_itself() -> None:
    fake = detector("pii", "T1")
    scan(
        "hello",
        fake,
        pol=policy(pii=DetectorPolicy(threshold=0.77, options={"entities": "email"})),
    )
    assert fake.seen_config is not None
    assert fake.seen_config.threshold == 0.77
    assert fake.seen_config.options == {"entities": "email"}


def test_a_missing_context_becomes_an_empty_one_not_none() -> None:
    # Detectors are allowed to read ctx unconditionally. groundedness in particular must
    # be able to see that sources is empty rather than crash on None.
    fake = detector("pii", "T1")
    scan("hello", fake, ctx=None)
    assert isinstance(fake.seen_context, Context)
    assert fake.seen_context.sources == ()


def test_the_caller_context_is_passed_through_unchanged() -> None:
    fake = detector("pii", "T1")
    ctx = Context(sources=("doc one",), locale="ro-RO")
    scan("hello", fake, ctx=ctx)
    assert fake.seen_context == ctx


def test_elapsed_ms_is_measured_and_not_negative() -> None:
    decision = scan("hello", detector("pii", "T1"))
    assert decision.elapsed_ms >= 0.0


# --------------------------------------------------------------------------- evidence


def test_the_record_describes_this_scan() -> None:
    pol = policy()
    decision = scan(
        "hello", detector("disclosure", "T0", "flag"), side="output", pol=pol
    )
    record = decision.evidence
    assert record.direction == "output"
    assert record.policy_id == pol.policy_id
    assert record.policy_hash == pol.hash
    assert record.verdict == decision.verdict


def test_the_record_attests_only_the_detectors_that_were_available() -> None:
    decision = scan("hello", detector("secrets", "T0"), detector("pii", "T1"))
    assert [a.id for a in decision.evidence.detectors] == ["pii", "secrets"]


def test_the_record_summary_drops_spans() -> None:
    decision = scan(
        PHONE_TEXT, detector("pii", "T1", "redact", label="phone", span=(5, 15))
    )
    assert decision.findings[0].span == (5, 15)
    assert not any("span" in s.model_dump() for s in decision.evidence.finding_summary)


def test_two_identical_scans_agree_on_everything_except_the_record_identity() -> None:
    # Constraint 6. record_id and timestamp must differ, because they say when this scan
    # happened; nothing else may.
    pol = policy()

    def once() -> Decision:
        return scan(
            PHONE_TEXT,
            detector("pii", "T1", "redact", label="phone", span=(5, 15)),
            pol=pol,
        )

    first, second = once(), once()
    assert (first.verdict, first.text, first.findings) == (
        second.verdict,
        second.text,
        second.findings,
    )
    assert first.evidence.record_id != second.evidence.record_id

    volatile = {"record_id", "timestamp"}
    a = first.evidence.model_dump()
    b = second.evidence.model_dump()
    assert {k: v for k, v in a.items() if k not in volatile} == {
        k: v for k, v in b.items() if k not in volatile
    }
