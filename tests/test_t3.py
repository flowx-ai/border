# SPDX-License-Identifier: Apache-2.0
"""The two T3 detectors, and the escalation that decides whether they run at all.

Real weights, no mocked sessions, per CLAUDE.md. Skipped with a readable reason when the
artifacts are absent, which on a fresh clone is both of them.

The file is in three parts. `topic_scope` works and is tested as working. `groundedness`
has correct plumbing and a model that cannot do the task, and the section on it is
written to keep that distinction sharp: the encoding, the label mapping, the no-source
behaviour and the truncation reporting are all asserted normally, and the model's
failure is pinned as an xfail so that fixing the corpus turns a passing test into a
signal rather than into silence. The escalation tests need no weights at all.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("HF_HUB_OFFLINE", "1")

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.groundedness import GroundednessDetector
from flowx_border.detectors.topic_scope import (
    LABEL_PREFIX,
    PATH_LIMIT,
    TopicScopeDetector,
    TopicScopeError,
    fold_path,
)

CFG = DetectorConfig(on_fail="flag", threshold=0.5)

SOURCE = (
    "Our savings account pays 3.1 percent annual interest. "
    "Withdrawals are free after twelve months."
)

TAXONOMY = {
    "taxonomy": {
        "allowed": [
            {
                "path": "banking/accounts",
                "description": "bank accounts, balances, statements and transfers",
            }
        ],
        "disallowed": [
            {
                "path": "banking/crypto",
                "description": "cryptocurrency, bitcoin and token speculation",
            },
            {
                "path": "health/medical",
                "description": "medical symptoms, diagnosis and treatment",
            },
        ],
    }
}


@pytest.fixture(scope="module")
def grounded() -> GroundednessDetector:
    from flowx_border.models.registry import ModelUnavailableError

    detector = GroundednessDetector()
    try:
        detector.warm()
    except ModelUnavailableError as error:
        pytest.skip(f"groundedness weights not available: {error}")
    return detector


@pytest.fixture(scope="module")
def scoped() -> TopicScopeDetector:
    from flowx_border.models.registry import ModelUnavailableError

    detector = TopicScopeDetector()
    try:
        detector.warm()
    except ModelUnavailableError as error:
        pytest.skip(f"topic_scope weights not available: {error}")
    return detector


# --------------------------------------------------------------- the path folding


def test_a_path_folds_into_a_label_safe_identifier() -> None:
    assert fold_path("banking/accounts") == "banking__accounts"
    assert fold_path("banking/loans and mortgages") == "banking__loans_and_mortgages"
    assert fold_path("Health/Medical Advice") == "health__medical_advice"


def test_folding_is_reversible_by_splitting_on_the_separator() -> None:
    # The property that makes a label useful in an audit record: somebody reading
    # `off_topic__banking__crypto` can recover which node fired.
    folded = fold_path("banking/crypto")
    assert folded.split("__") == ["banking", "crypto"]


def test_a_path_too_long_for_a_label_is_refused_rather_than_truncated(
    scoped: TopicScopeDetector,
) -> None:
    """A truncated path in an audit record is a wrong path, not a shorter one."""
    long_path = "banking/" + "extremely_long_segment_name/" * 4 + "leaf"
    cfg = DetectorConfig(
        on_fail="flag",
        options={"taxonomy": {"disallowed": [{"path": long_path}]}},
    )
    scoped.forget()
    with pytest.raises(TopicScopeError, match="Shorten the path"):
        scoped.run("anything", cfg, Context())


def test_the_prefix_is_counted_against_the_label_limit() -> None:
    # The bug this pins: validating the folded path against 64 and then prefixing it
    # with eleven more characters, which turns "cannot truncate" into a truncation.
    assert 64 - len(LABEL_PREFIX) == PATH_LIMIT


# ------------------------------------------------------------------- topic_scope


def test_an_in_scope_question_produces_no_finding(scoped: TopicScopeDetector) -> None:
    cfg = DetectorConfig(on_fail="flag", threshold=0.5, options=TAXONOMY)
    assert (
        scoped.run("How do I transfer money between my accounts?", cfg, Context()) == []
    )


def test_a_disallowed_topic_is_found_and_names_its_node(
    scoped: TopicScopeDetector,
) -> None:
    cfg = DetectorConfig(on_fail="flag", threshold=0.5, options=TAXONOMY)
    findings = scoped.run("Should I put my savings into bitcoin?", cfg, Context())
    assert len(findings) == 1
    assert findings[0].label == "off_topic__banking__crypto"
    assert findings[0].score > 0.5


def test_the_nearest_disallowed_node_wins_rather_than_the_first(
    scoped: TopicScopeDetector,
) -> None:
    # Two disallowed nodes, and the one that fires has to be the one the text is about.
    # A detector that reported whichever node came first in the file would look correct
    # on a one-node taxonomy and be wrong on every real one.
    cfg = DetectorConfig(on_fail="flag", threshold=0.5, options=TAXONOMY)
    findings = scoped.run("I have a sharp pain in my chest.", cfg, Context())
    assert len(findings) == 1
    assert findings[0].label == "off_topic__health__medical"


def test_an_unconfigured_taxonomy_is_reported_rather_than_passed(
    scoped: TopicScopeDetector,
) -> None:
    findings = scoped.run("anything at all", DetectorConfig(on_fail="block"), Context())
    assert [f.label for f in findings] == ["topic_scope_unconfigured"]
    # log, not the policy's action: the caller is told the check could not run and is
    # not blocked for a configuration gap.
    assert findings[0].action == "log"


def test_an_edited_description_is_not_served_from_the_cache(
    scoped: TopicScopeDetector,
) -> None:
    """The taxonomy cache is keyed by content, so a policy edit takes effect.

    Keyed by identity or by node count, an operator who corrected a description would
    keep getting the old vectors until the process restarted.
    """
    narrow = {
        "taxonomy": {
            "disallowed": [{"path": "topic/one", "description": "cryptocurrency"}]
        }
    }
    edited = {
        "taxonomy": {"disallowed": [{"path": "topic/one", "description": "cardiology"}]}
    }
    text = "Should I buy bitcoin?"
    first = scoped.run(text, DetectorConfig(threshold=0.5, options=narrow), Context())
    second = scoped.run(text, DetectorConfig(threshold=0.5, options=edited), Context())
    assert first and first[0].score > (second[0].score if second else 0.0)


def test_the_score_is_inside_the_score_range(scoped: TopicScopeDetector) -> None:
    # Cosine is -1..1 and Score is 0..1. Without the rescale, an unrelated input would
    # raise a validation error from pydantic instead of scoring low.
    cfg = DetectorConfig(on_fail="flag", threshold=0.0, options=TAXONOMY)
    for finding in scoped.run("Völlig anderes Thema, danke.", cfg, Context()):
        assert 0.0 <= finding.score <= 1.0


def test_empty_text_is_not_scored(scoped: TopicScopeDetector) -> None:
    cfg = DetectorConfig(on_fail="flag", threshold=0.0, options=TAXONOMY)
    assert scoped.run("   ", cfg, Context()) == []


# ------------------------------------------------------------------ groundedness


def test_no_sources_records_a_no_op_rather_than_passing(
    grounded: GroundednessDetector,
) -> None:
    """The Phase 5 definition of done, and the config's `no_sources_behaviour`."""
    findings = grounded.run("The rate is 3.1 percent.", CFG, Context())
    assert [f.label for f in findings] == ["groundedness_unverifiable"]
    assert findings[0].action == "log"


def test_sources_may_come_from_the_policy_as_well_as_the_context(
    grounded: GroundednessDetector,
) -> None:
    cfg = DetectorConfig(on_fail="flag", threshold=0.5, options={"sources": [SOURCE]})
    findings = grounded.run("Withdrawals are free after twelve months.", cfg, Context())
    assert "groundedness_unverifiable" not in [f.label for f in findings]


def test_text_with_no_claim_long_enough_is_reported(
    grounded: GroundednessDetector,
) -> None:
    # "Nothing to check" and "everything checked out" are different answers, and a
    # record that cannot tell them apart is the failure this library refuses.
    findings = grounded.run("Ok.", CFG, Context(sources=(SOURCE,)))
    assert [f.label for f in findings] == ["groundedness_no_claims"]


def test_a_span_points_at_the_sentence_it_judged(
    grounded: GroundednessDetector,
) -> None:
    text = "Withdrawals are free after twelve months. The fee is nine hundred euro."
    for finding in grounded.run(text, CFG, Context(sources=(SOURCE,))):
        if finding.span is None:
            continue
        start, end = finding.span
        assert text[start:end].strip()
        assert 0 <= start < end <= len(text)


def test_truncation_is_reported_rather_than_silent(
    grounded: GroundednessDetector,
) -> None:
    """A scan that looked at 2 of 40 sentences must not read as a clean scan."""
    text = " ".join(f"Sentence number {n} makes a claim about fees." for n in range(6))
    cfg = DetectorConfig(
        on_fail="flag", threshold=0.5, options={"max_sentences": 2, "sources": [SOURCE]}
    )
    labels = [f.label for f in grounded.run(text, cfg, Context())]
    assert "groundedness_truncated_sentences" in labels


def test_a_verbatim_claim_is_supported(grounded: GroundednessDetector) -> None:
    # The one direction the model does get right, and the reason the plumbing can be
    # trusted: pair order, template and label mapping all have to be correct for this.
    findings = grounded.run(
        "Withdrawals are free after twelve months.", CFG, Context(sources=(SOURCE,))
    )
    assert [f for f in findings if f.action != "log"] == []


def test_the_label_map_is_checked_against_what_this_detector_means(
    grounded: GroundednessDetector,
) -> None:
    # A re-export that renamed `supported` would invert every verdict silently.
    assert grounded._labels is not None
    assert set(grounded._labels.values()) == {
        "supported",
        "unsupported",
        "contradicted",
    }


@pytest.mark.xfail(
    reason=(
        "The trained groundedness model scores string similarity rather than "
        "entailment. Measured 2026-08-11: a verbatim copy reads supported at 0.9998 "
        "and a paraphrase of the same fact reads contradicted at 0.9988, as does a "
        "strictly weaker claim that the source fully supports. An LLM answer "
        "paraphrases its sources by definition, so this model would flag nearly every "
        "grounded answer. Its 0.882 exact-match accuracy is real but measures copy "
        "detection, because the test split shares the corpus flaw: the supported class"
        " was generated as near-copies. The fix is corpus-side, generating supported "
        "examples as paraphrases. This is xfail rather than deleted so that "
        "regenerating the corpus turns it into a signal."
    ),
    strict=True,
)
def test_a_paraphrase_of_the_source_is_supported(
    grounded: GroundednessDetector,
) -> None:
    scored = grounded.judge(
        "Withdrawals are free after twelve months.",
        "You can withdraw at no cost once a year has passed.",
        1,
    )
    assert max(scored, key=lambda label: scored[label]) == "supported"


@pytest.mark.xfail(
    reason=(
        "Same root cause as the paraphrase failure: a claim the source fully supports, "
        "stated more weakly, reads as contradicted. Kept separate because it is the "
        "case an operator would hit most often, a summary shorter than its source."
    ),
    strict=True,
)
def test_a_weaker_claim_than_the_source_is_supported(
    grounded: GroundednessDetector,
) -> None:
    scored = grounded.judge(
        "The fee is 5 EUR and applies monthly.", "The fee is 5 EUR.", 1
    )
    assert max(scored, key=lambda label: scored[label]) == "supported"


# -------------------------------------------------------------------- escalation


def a_policy(**detectors: dict[str, object]) -> object:
    from flowx_border.policy import DetectorPolicy, Policy

    return Policy(
        policy_id="t3",
        version=1,
        fail_mode=dict.fromkeys(("T0", "T1", "T2", "T3"), "open"),
        detectors={
            name: DetectorPolicy(**entry)  # type: ignore[arg-type]
            for name, entry in detectors.items()
        },
    )


def test_t3_does_not_run_when_nothing_flagged() -> None:
    """The point of the tier. T3 is 300 ms, so it must not run on a clean scan."""
    from flowx_border.engine import run_scan

    policy = a_policy(
        secrets={"enabled": True, "on_fail": "redact"},
        topic_scope={"enabled": True, "on_fail": "flag"},
    )
    decision = run_scan("a perfectly ordinary question", "input", policy, None, {})
    assert "T3" not in decision.tiers_run


def test_an_escalated_scan_records_what_escalated_it() -> None:
    """The Phase 5 definition of done: findings name the escalation reason.

    Emitted by the engine rather than by each T3 detector, because the detector is
    handed text and a config and knows nothing about the history of the scan.
    """
    from flowx_border.detectors.base import Context as Ctx
    from flowx_border.engine import run_scan
    from flowx_border.types import Finding

    class AlwaysFlags:
        id = "secrets"
        tier = "T0"
        sides = frozenset({"input"})

        def warm(self) -> None:
            return None

        def run(self, text: str, cfg: DetectorConfig, ctx: Ctx) -> list[Finding]:
            return [
                Finding(
                    detector_id="secrets",
                    tier="T0",
                    label="aws_access_key_id",
                    score=1.0,
                    action="redact",
                    span=(0, 4),
                )
            ]

    class Records:
        id = "topic_scope"
        tier = "T3"
        sides = frozenset({"input"})

        def warm(self) -> None:
            return None

        def run(self, text: str, cfg: DetectorConfig, ctx: Ctx) -> list[Finding]:
            return []

    policy = a_policy(
        secrets={"enabled": True, "on_fail": "flag"},
        topic_scope={"enabled": True, "on_fail": "flag"},
    )
    decision = run_scan(
        "some text",
        "input",
        policy,
        None,
        {"secrets": AlwaysFlags(), "topic_scope": Records()},
    )
    assert "T3" in decision.tiers_run
    reasons = [f.label for f in decision.findings if f.label.startswith("escalated_by")]
    assert reasons == ["escalated_by_secrets"]


def test_always_true_records_that_reason_instead() -> None:
    from flowx_border.detectors.base import Context as Ctx
    from flowx_border.engine import run_scan
    from flowx_border.types import Finding

    class Quiet:
        id = "topic_scope"
        tier = "T3"
        sides = frozenset({"input"})

        def warm(self) -> None:
            return None

        def run(self, text: str, cfg: DetectorConfig, ctx: Ctx) -> list[Finding]:
            return []

    policy = a_policy(
        topic_scope={"enabled": True, "on_fail": "flag", "always": True},
    )
    decision = run_scan("some text", "input", policy, None, {"topic_scope": Quiet()})
    reasons = [f.label for f in decision.findings if f.label.startswith("escalated_by")]
    assert reasons == ["escalated_by_policy_always"]


def test_the_escalation_reason_does_not_change_the_verdict() -> None:
    # It is action `log`, so it belongs in the record and not in the decision.
    from flowx_border.detectors.base import Context as Ctx
    from flowx_border.engine import run_scan
    from flowx_border.types import Finding

    class Quiet:
        id = "topic_scope"
        tier = "T3"
        sides = frozenset({"input"})

        def warm(self) -> None:
            return None

        def run(self, text: str, cfg: DetectorConfig, ctx: Ctx) -> list[Finding]:
            return []

    policy = a_policy(topic_scope={"enabled": True, "on_fail": "block", "always": True})
    decision = run_scan("text", "input", policy, None, {"topic_scope": Quiet()})
    assert decision.verdict == "allow"


def test_the_escalation_record_does_not_read_as_a_detection() -> None:
    """A consumer taking the highest score per detector must not see T3 as objecting.

    The regression this pins, found on 2026-08-11: the escalation entry carried score
    1.0, and the llm-guard shim reports `results_valid[scanner] = score == 0.0`. So a
    clean output-side scan with `url_reachability` enabled came back invalid, because
    the engine had recorded why the tier ran using a field that means confidence. Zero
    is the honest value: the label carries the provenance and nothing was detected.
    """
    from flowx_border.detectors.base import Context as Ctx
    from flowx_border.engine import run_scan
    from flowx_border.types import Finding

    class Quiet:
        id = "topic_scope"
        tier = "T3"
        sides = frozenset({"input"})

        def warm(self) -> None:
            return None

        def run(self, text: str, cfg: DetectorConfig, ctx: Ctx) -> list[Finding]:
            return []

    policy = a_policy(topic_scope={"enabled": True, "on_fail": "flag", "always": True})
    decision = run_scan("text", "input", policy, None, {"topic_scope": Quiet()})
    worst = max(
        (f.score for f in decision.findings if f.detector_id == "topic_scope"),
        default=0.0,
    )
    assert worst == 0.0
