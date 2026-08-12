# SPDX-License-Identifier: Apache-2.0
"""Tests for the summary support detector, and the thing it deliberately cannot do.

The detector asks whether each sentence of a summary has a close counterpart in the
source. It answers with string overlap, and the most important test in this file is the
one that pins what that costs: a true paraphrase reads as unsupported, because it shares
no words.

That is a contract rather than a defect, and it is tested as one. The alternative would
be to imply entailment, and this project already has a detector that implied entailment
and did not deliver it: `groundedness`, whose model turned out to recognise its
generator's paraphrase style rather than compare a claim to a source. A detector honest
about counting shared words is worth more than one that overstates.
"""

from __future__ import annotations

import pytest

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.summary_support import (
    SummarySupportDetector,
    SummarySupportError,
)

CFG = DetectorConfig(on_fail="flag")

SOURCE = (
    "The account pays 3.1 percent annual interest, calculated daily and credited "
    "on the last business day of each month. Withdrawals made within the first "
    "twelve months "
    "incur a handling fee of 5 EUR per transaction. After twelve months have elapsed, "
    "withdrawals are free of charge and may be made without notice."
)


@pytest.fixture
def detector() -> SummarySupportDetector:
    found = SummarySupportDetector()
    found.warm()
    return found


def sourced() -> Context:
    return Context(sources=(SOURCE,))


# ------------------------------------------------------------------ what it is for


def test_a_sentence_taken_from_the_source_is_supported(
    detector: SummarySupportDetector,
) -> None:
    sentence = (
        "Withdrawals made within the first twelve months incur a handling fee of 5 EUR "
        "per transaction."
    )
    assert detector.run(sentence, CFG, sourced()) == []


def test_a_lightly_reworded_sentence_is_still_supported(
    detector: SummarySupportDetector,
) -> None:
    # The reason the threshold is 0.75 rather than 1.0: dropping a few words or
    # reordering a clause is what an extractive summariser does, and it is not an
    # invention.
    sentence = (
        "Withdrawals within the first twelve months incur a handling fee of 5 EUR."
    )
    assert detector.run(sentence, CFG, sourced()) == []


def test_an_invented_sentence_is_reported(detector: SummarySupportDetector) -> None:
    found = detector.run(
        "The account includes free travel insurance for all holders.", CFG, sourced()
    )
    assert [f.label for f in found] == ["unsupported_sentence"]
    assert found[0].score > 0.0


def test_the_span_points_at_the_sentence_it_judged(
    detector: SummarySupportDetector,
) -> None:
    text = (
        "After twelve months have elapsed, withdrawals are free of charge. "
        "The bank also waives the annual card fee for every customer."
    )
    found = detector.run(text, CFG, sourced())
    assert len(found) == 1
    start, end = found[0].span or (0, 0)
    assert "annual card fee" in text[start:end]


def test_the_score_grows_with_the_distance_from_the_source(
    detector: SummarySupportDetector,
) -> None:
    """A policy threshold should be able to act on the degree, not only the fact.

    Both sentences are scored at the same threshold, deliberately. The score is the
    shortfall normalised by the threshold, so a score from a 0.95 run and one from a
    0.75 run are not comparable, and the first version of this test compared them and
    failed for that reason rather than because the detector was wrong.
    """
    strict = DetectorConfig(on_fail="flag", options={"similarity": 0.95})
    near = detector.run(
        "Withdrawals made within the first twelve months incur a handling fee of "
        "5 EUR.",
        strict,
        sourced(),
    )
    far = detector.run(
        "Sharks are the largest fish in the northern Atlantic ocean.", strict, sourced()
    )
    assert near and far, "both should fall short of a 0.95 threshold"
    assert far[0].score > near[0].score, (
        f"a sentence about sharks scored {far[0].score} and a near copy scored "
        f"{near[0].score}; the shortfall should grow with the distance"
    )


# ----------------------------------------------------- what it deliberately cannot do


def test_a_true_paraphrase_reads_as_unsupported(
    detector: SummarySupportDetector,
) -> None:
    """The documented limitation, pinned so nobody mistakes this for entailment.

    "You pay nothing to take money out once a year has passed" is exactly what the
    source says and shares almost none of its words, so it scores as maximally
    unsupported. Anyone reaching for this detector to check groundedness needs to meet
    this test first.
    """
    paraphrase = detector.run(
        "You pay nothing to take money out once a year has passed.", CFG, sourced()
    )
    assert [f.label for f in paraphrase] == ["unsupported_sentence"]

    # The sharpest available statement of the limitation: a true paraphrase and a
    # sentence about sharks score within a hundredth of each other, 0.509 and 0.501 as
    # measured on 2026-08-12. An overlap measure cannot tell a correct restatement from
    # an unrelated claim, because neither shares vocabulary with the source. Anyone
    # tempted to read this detector's score as a degree of unsupportedness should read
    # that number twice.
    unrelated = detector.run(
        "Sharks are the largest fish in the northern Atlantic ocean.", CFG, sourced()
    )
    assert unrelated
    assert abs(paraphrase[0].score - unrelated[0].score) < 0.05, (
        f"the paraphrase scored {paraphrase[0].score} and an unrelated sentence "
        f"{unrelated[0].score}. If those have separated, this detector has stopped "
        "being a pure overlap measure and its docstring needs rewriting."
    )


def test_a_copied_sentence_with_its_meaning_reversed_reads_as_supported(
    detector: SummarySupportDetector,
) -> None:
    """The other half of the same limitation, and the more dangerous half.

    Inserting a negation changes the claim completely and barely moves the overlap, so
    this detector calls it supported. It is in the docstring and it is here, because a
    caller who only reads the label would draw the opposite conclusion.
    """
    sentence = (
        "Withdrawals made within the first twelve months do not incur a handling "
        "fee of 5 EUR per transaction."
    )
    assert detector.run(sentence, CFG, sourced()) == [], (
        "a negated copy is still mostly the same words, so an overlap measure "
        "accepts it. If this now reports, the detector has become something other "
        "than an overlap measure and its docstring needs rewriting."
    )


# -------------------------------------------------- saying so rather than passing


def test_no_source_is_reported_rather_than_passed(
    detector: SummarySupportDetector,
) -> None:
    found = detector.run("Any claim at all about the account.", CFG, Context())
    assert [f.label for f in found] == ["summary_support_unverifiable"]
    # log rather than the policy's action: an absent source is a configuration gap, and
    # blocking a response over one would make the detector unusable without retrieval.
    assert found[0].action == "log"


def test_a_source_of_only_fragments_says_so(detector: SummarySupportDetector) -> None:
    found = detector.run(
        "The account pays interest monthly on the closing balance.",
        CFG,
        Context(sources=("Ok. Yes. Fine.",)),
    )
    assert [f.label for f in found] == ["summary_support_no_source_sentences"]


def test_sources_may_come_from_the_policy(detector: SummarySupportDetector) -> None:
    cfg = DetectorConfig(on_fail="flag", options={"sources": [SOURCE]})
    sentence = "After twelve months have elapsed, withdrawals are free of charge."
    assert detector.run(sentence, cfg, Context()) == []


def test_truncation_is_reported_rather_than_silent(
    detector: SummarySupportDetector,
) -> None:
    text = " ".join(
        f"Claim number {n} about the account and its fees." for n in range(8)
    )
    cfg = DetectorConfig(on_fail="flag", options={"max_sentences": 2})
    labels = [f.label for f in detector.run(text, cfg, sourced())]
    assert "summary_support_truncated" in labels


def test_a_fragment_is_not_judged(detector: SummarySupportDetector) -> None:
    # "Thanks." carries no claim, and a short string matches something in any long
    # source.
    assert detector.run("Ok.", CFG, sourced()) == []


def test_a_zero_similarity_is_refused(detector: SummarySupportDetector) -> None:
    cfg = DetectorConfig(on_fail="flag", options={"similarity": 0.0})
    with pytest.raises(SummarySupportError, match="above 0"):
        detector.run("Any claim about the account.", cfg, sourced())


# ------------------------------------------------------------- the languages


@pytest.mark.parametrize(
    ("language", "source", "supported", "invented"),
    [
        (
            "ro",
            "Contul plătește o rată anuală de 3,1 procente. Retragerile în primele "
            "douăsprezece luni au un comision de 5 EUR.",
            "Retragerile în primele douăsprezece luni au un comision de 5 EUR.",
            "Contul include asigurare de călătorie gratuită pentru toți clienții.",
        ),
        (
            "de",
            "Das Konto zahlt einen Jahreszins von 3,1 Prozent. Abhebungen in den "
            "ersten zwölf Monaten kosten eine Gebühr von 5 EUR.",
            "Abhebungen in den ersten zwölf Monaten kosten eine Gebühr von 5 EUR.",
            "Das Konto beinhaltet eine kostenlose Reiseversicherung für alle Kunden.",
        ),
        (
            "el",
            "Ο λογαριασμός αποδίδει ετήσιο επιτόκιο 3,1 τοις εκατό. Οι αναλήψεις στους "
            "πρώτους δώδεκα μήνες έχουν χρέωση 5 EUR.",
            "Οι αναλήψεις στους πρώτους δώδεκα μήνες έχουν χρέωση 5 EUR.",
            "Ο λογαριασμός περιλαμβάνει δωρεάν ταξιδιωτική ασφάλιση για όλους.",
        ),
        (
            "tr",
            "Hesap yıllık yüzde 3,1 faiz ödüyor. İlk on iki ayda yapılan çekimler için "
            "5 EUR ücret alınır.",
            "İlk on iki ayda yapılan çekimler için 5 EUR ücret alınır.",
            "Hesap tüm müşteriler için ücretsiz seyahat sigortası içerir.",
        ),
    ],
)
def test_it_works_the_same_in_other_languages(
    detector: SummarySupportDetector,
    language: str,
    source: str,
    supported: str,
    invented: str,
) -> None:
    """A sample of the 26, including a non-Latin script and an agglutinative language.

    The folding and sentence splitting this relies on are the shared multilingual core,
    which has its own tests. What this checks is that the detector composes with them:
    that a sentence lifted from a Greek source is recognised, and an invented Turkish
    one is not.
    """
    context = Context(sources=(source,))
    assert detector.run(supported, CFG, context) == [], (
        f"{language}: extract not recognised"
    )
    found = detector.run(invented, CFG, context)
    assert [f.label for f in found] == ["unsupported_sentence"], (
        f"{language}: invention not reported"
    )
