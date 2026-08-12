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


#: A source of the length the model was trained on, 163 to 1019 characters with a median
#: of 340. The earlier version of these tests used a single sentence, which is outside
#: that range, and conflated "the model cannot do this" with "the model has never seen
#: an input shaped like this". Both turned out to be happening, and they needed
#: separating.
PROBE_SOURCE = (
    "Section 4.2 sets out the terms applicable to the savings account. The account pays"
    " 3.1 percent annual interest, calculated daily and credited on the last business "
    "day of each month. Withdrawals made within the first twelve months of opening "
    "incur a handling fee of 5 EUR per transaction. After twelve months have elapsed, "
    "withdrawals are free of charge and may be made without notice. The bank reserves "
    "the right to vary the interest rate with thirty days written notice to the account"
    " holder."
)


@pytest.mark.parametrize(
    ("case", "sentence", "expected"),
    [
        (
            "restatement",
            "After twelve months have elapsed, withdrawals are free of charge.",
            "supported",
        ),
        ("invention", "The account includes free travel insurance.", "unsupported"),
        (
            "contradiction",
            "Withdrawals are free from the day the account opens.",
            "contradicted",
        ),
    ],
)
def test_the_cases_the_model_does_get_right(
    grounded: GroundednessDetector, case: str, sentence: str, expected: str
) -> None:
    """Pinned so that fixing the paraphrase failure cannot quietly break these.

    Measured 2026-08-12 against a source of the trained length: a near-verbatim
    restatement reads supported at 0.9999, an invention reads unsupported, and a real
    contradiction reads contradicted. Whatever the corpus becomes, it has to keep these.
    """
    scored = grounded.judge(PROBE_SOURCE, sentence, 1)
    assert max(scored, key=lambda label: scored[label]) == expected, (
        f"{case}: { ({k: round(v, 4) for k, v in scored.items()}) }"
    )


@pytest.mark.xfail(
    reason=(
        "The model generalises inside its generator's style and not outside it, and its"
        " own test split cannot detect that because the split came from the same "
        "generator. Measured 2026-08-12: it scores 0.864 on the paraphrase register of "
        "its test set, whose examples share only 0.165 of their content words with "
        "their source, so it is demonstrably not counting words. Against a hand-written"
        " paraphrase of a stated fact, at the same source length, it reads contradicted"
        " at 0.0013. An LLM answer paraphrases its sources in its own way rather than "
        "in this generator's way, which is the case that matters. Two earlier readings "
        "of this were wrong: that the model scores string similarity, disproved by the "
        "paraphrase and lexical_overlap registers, and that the supported class was "
        "generated as near-copies, disproved by measuring the overlap. The fix is a "
        "corpus with stylistic variety plus an evaluation set produced some other way, "
        "and this xfail is the signal for when that lands."
    ),
    strict=True,
)
def test_a_hand_written_paraphrase_is_supported(grounded: GroundednessDetector) -> None:
    scored = grounded.judge(
        PROBE_SOURCE,
        "You can take money out at no cost once a year has gone by.",
        1,
    )
    assert max(scored, key=lambda label: scored[label]) == "supported"


@pytest.mark.xfail(
    reason=(
        "Same root cause as the paraphrase failure and the case an operator meets most "
        "often, a summary that says less than its source. The source states that early "
        "withdrawals incur a handling fee; a sentence asserting only that a fee exists "
        "reads contradicted."
    ),
    strict=True,
)
def test_a_claim_weaker_than_the_source_is_supported(
    grounded: GroundednessDetector,
) -> None:
    scored = grounded.judge(
        PROBE_SOURCE, "There is a handling fee for early withdrawals.", 1
    )
    assert max(scored, key=lambda label: scored[label]) == "supported"


@pytest.mark.xfail(
    reason=(
        "Dropping two words flips the verdict. 'After twelve months have elapsed, "
        "withdrawals are free of charge' reads supported at 0.9999; the same claim as "
        "'Withdrawals are free of charge after twelve months' reads contradicted at "
        "0.0002. Same source, same meaning, two fewer words. It is the same root cause "
        "as the paraphrase failure, in its smallest form."
    ),
    strict=True,
)
def test_a_restatement_survives_losing_two_words(
    grounded: GroundednessDetector,
) -> None:
    scored = grounded.judge(
        PROBE_SOURCE, "Withdrawals are free of charge after twelve months.", 1
    )
    assert max(scored, key=lambda label: scored[label]) == "supported"


def test_a_source_far_shorter_than_the_trained_range_is_a_different_question(
    grounded: GroundednessDetector,
) -> None:
    """Source length matters, separately from style, and this records by how much.

    Measured 2026-08-12: the near-verbatim restatement reads supported at 0.9999 against
    a 500 character source and contradicted at 0.0001 against a single sentence. The
    model was trained on 163 to 1019 characters. So a caller passing one retrieved
    sentence as a source is outside the distribution, and that is worth knowing
    separately from the style problem, because it is fixable by the caller.
    """
    sentence = "After twelve months have elapsed, withdrawals are free of charge."
    long_source = grounded.judge(PROBE_SOURCE, sentence, 1)
    short_source = grounded.judge(
        "Withdrawals are free after twelve months.", sentence, 1
    )
    assert max(long_source, key=lambda k: long_source[k]) == "supported"
    assert max(short_source, key=lambda k: short_source[k]) != "supported", (
        "a one-sentence source now works, so this limitation has been fixed and the "
        "note in models/registry.py should be updated"
    )


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


def test_the_verdict_depends_on_the_source_it_was_given(
    grounded: GroundednessDetector,
) -> None:
    """The measurement that found what is actually wrong with this corpus.

    A groundedness verdict must depend on the source. If swapping the source for an
    unrelated passage leaves the verdict unchanged, the model is reading the sentence
    and nothing else, and the accuracy it reports is style classification wearing the
    name of entailment.

    Measured 2026-08-12 over the test split, fourteen examples per register, each judged
    against its true source and against a source from a different register in a
    different language:

        register                 label          right source   unrelated source
        numeric_contradiction    contradicted           0.93               0.00
        negation_contradiction   contradicted           0.79               0.00
        verbatim_support         supported              0.93               0.36
        lexical_overlap          unsupported            0.93               0.50
        multi_sentence_support   supported              0.64               0.71
        unstated_detail          unsupported            0.93               0.79
        paraphrase               supported              0.86               0.86
        plausible_invention      unsupported            1.00               0.86

    Four of the eight barely move. `paraphrase` is identical, and
    `multi_sentence_support` does better with the wrong source than the right one. The
    corpus leaks its label through the candidate sentence's style, because every request
    asked for ten items of one register with the register named in the prompt, so each
    class came out stylistically uniform.

    This asserts the property for the two registers where the model does compare, so the
    fix cannot regress them, and leaves the leak itself as the xfail below.
    """
    supporting = PROBE_SOURCE
    unrelated = (
        "Anexa 3 descrie procedura de rambursare a cheltuielilor de deplasare. Cererile"
        " se depun in termen de treizeci de zile de la incheierea deplasarii, insotite "
        "de documente justificative. Sumele aprobate se achita prin virament bancar in "
        "cel mult cincisprezece zile lucratoare de la aprobare."
    )
    contradiction = "Withdrawals are free from the day the account opens."
    assert (
        max(
            (scored := grounded.judge(supporting, contradiction, 1)),
            key=lambda label: scored[label],
        )
        == "contradicted"
    )
    swapped = grounded.judge(unrelated, contradiction, 1)
    assert max(swapped, key=lambda label: swapped[label]) != "contradicted", (
        "a contradiction verdict survived swapping the source, so even the registers "
        "that did compare have stopped comparing"
    )


@pytest.mark.xfail(
    reason=(
        "The leak itself, quantified in the docstring above. A supported verdict for a "
        "paraphrase survives swapping the source for an unrelated passage in another "
        "language, which means it was never a judgement about the source. The corpus "
        "needs the same candidate sentence to appear against both a source that "
        "supports it and one that does not, so that style cannot predict the label by "
        "construction. That also needs two changes to the harness: Corpus.add rejects "
        "the same sentence twice as a label_conflict, which is right for a single-text "
        "task and backwards for a relational one, and Corpus.write strata by language "
        "and register, which would put the two halves of such a pair in different "
        "splits."
    ),
    strict=True,
)
def test_a_supported_verdict_does_not_survive_an_unrelated_source(
    grounded: GroundednessDetector,
) -> None:
    unrelated = (
        "Anexa 3 descrie procedura de rambursare a cheltuielilor de deplasare. Cererile"
        " se depun in termen de treizeci de zile de la incheierea deplasarii, insotite "
        "de documente justificative."
    )
    # A real paraphrase-register sentence from the test split. Against its own source it
    # scores 0.9999 supported, and against this unrelated Romanian passage about travel
    # expense reimbursement it also scores 0.9999. Same sentence, same confidence,
    # nothing in common. Hand-written paraphrases cannot show this because the model
    # rejects those outright; the leak is specific to sentences written in the
    # generator's own style.
    from_the_corpus = (
        "Sales increased to nearly \u00a32.85 billion in 2023, up from the "
        "previous year, with operating costs of approximately \u00a31.92 billion "
        "generating an operating surplus of roughly \u00a3920 million."
    )
    scored = grounded.judge(unrelated, from_the_corpus, 1)
    assert max(scored, key=lambda label: scored[label]) != "supported", (
        f"p(supported)={scored['supported']:.4f} against an unrelated source"
    )
