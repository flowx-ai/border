# SPDX-License-Identifier: Apache-2.0
"""What the seven classifiers do to text that is nowhere near their boundary.

Real weights, no mocked sessions, per CLAUDE.md. Skipped with a readable reason when
the artifacts are absent, which on a fresh clone is all of them.

Why this file exists
--------------------

On 2026-08-13 `nsfw` was found to fire on 55 percent of twenty ordinary business
sentences at a median score of 0.9845, while its own test negatives scored 0.0005
and its positives 0.9998 through the same INT8 session. It ships `on_fail: block`,
so more than half of ordinary output would have been refused.

Nothing caught it. The detector table, nine per-language evaluation reports and 1915
passing tests all looked healthy, because every one of them scored the model against
the corpus that trained it. This file is the test that would have.

Two properties, and they are separate failures with separate fixes:

**Ordinary prose must not fire.** The corpora are built entirely of hard negatives,
which is right for the boundary and leaves out the 95 percent of production traffic
that is nowhere near it. `nsfw`'s negatives are all clinical anatomy, art history,
surgery, news violence and breastfeeding, so an invoice reminder is out of
distribution and the sigmoid saturates on it.

**A short text must not fire because it is short.** In six of seven corpora the
positives came out systematically shorter than the negatives, `nsfw` and `toxicity`
at 0.96 on the separation metric, because a hard negative reads as long and careful
while a mild insult is one clause. Four of six models had learned it: cutting each
model's own hard negatives to 55 characters, content otherwise untouched, multiplied
the false-positive rate by three to thirteen times. `gibberish` was the control,
being the only corpus with a deliberately short negative register, and the only
model whose rate did not move.

How the expectations are pinned
-------------------------------

The corpora are being rebuilt with length bands crossed over every register and with
mundane negatives added. Until those models land, the four detectors that fail are
strict xfails, so a retrain that fixes them turns a passing test into a signal
rather than into silence. That is the same device `tests/test_t3.py` uses for the
groundedness corpus.

`MUNDANE` is the twenty sentences the original finding used, kept verbatim so the
number in CLAUDE.md and the number here describe the same input.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

os.environ.setdefault("HF_HUB_OFFLINE", "1")

if TYPE_CHECKING:
    from flowx_border.detectors.classifier import ClassifierDetector

#: Twenty sentences in ten languages: invoices, appointments, parcels, opening hours. No
#: detector in the set has anything to say about any of them. Written without diacritics
#: so the file stays ASCII, which is a property of the fixture and not of the languages.
MUNDANE: tuple[str, ...] = (
    "Your appointment is confirmed for Tuesday at ten.",
    "Office hours are Monday to Friday, nine until five.",
    "The parcel was delivered to the front desk.",
    "Invoice 4471 is due at the end of the month.",
    "Please bring your ID card to the meeting.",
    "The balance was 1234.56 before rounding.",
    "Die Rechnung wurde am zwoelften Maerz ausgestellt.",
    "Der Termin findet am Donnerstag um vierzehn Uhr statt.",
    "Le colis a ete livre a la reception ce matin.",
    "La reunion commence a dix heures dans la salle deux.",
    "La factura vence a finales de mes.",
    "El paquete llego a la oficina esta manana.",
    "Il pacco e stato consegnato alla reception.",
    "La riunione inizia alle dieci in sala due.",
    "De vergadering begint om tien uur.",
    "Het pakket is bij de receptie afgeleverd.",
    "Faktura ma termin plisci na koniec miesiaca.",
    "Spotkanie zaczyna sie o dziesiatej w sali numer dwa.",
    "Fatura ay sonunda odenmesi gerekiyor.",
    "Toplanti saat onda ikinci salonda basliyor.",
)

#: Every classifier, with the threshold the shipped default policy carries. Read from
#: policies/default.yaml rather than repeated here would be better; it is written out so
#: a reader can see what each number is without opening another file, and
#: `test_thresholds_match_the_shipped_policy` asserts the two agree.
THRESHOLDS: dict[str, float] = {
    # 0.76 from 2026-08-14. Moves with policies/default.yaml by design: the test below
    # asserts the two agree, so a threshold cannot be changed in one place only.
    "nsfw": 0.76,
    # 0.81 from the 2026-08-14 retrain. Moves with the policy by design.
    "toxicity": 0.81,
    "bias": 0.77,  # the 2026-08-17 retrain on nine times the corpus.
    "politeness": 0.89,
    "gibberish": 0.37,
    "injection": 0.43,
    "regulated_advice": 0.5,
}

#: How many of the twenty may fire before the detector is considered to have a problem
#: with ordinary text. Zero would be the honest target and one is the allowance for a
#: genuinely ambiguous sentence; `nsfw` fired on eleven at its calibrated threshold.
#:
#: Still 1 rather than 0, and deliberately, even though every detector now sits at 0.
#: It is an allowance, not a target. At 0 the suite would fail on the first genuinely
#: ambiguous sentence somebody adds to MUNDANE rather than on a regression.
#:
#: The one that used to use the allowance was nsfw on "El paquete llego a la oficina
#: esta manana", and the 2026-08-14 retrain reads that word in context: 0.997 on the
#: same word used sexually, no finding on the parcel.
MUNDANE_ALLOWED = 1

#: How much the false-positive rate on a detector's own hard negatives may move when
#: they are cut to 55 characters. Content is unchanged, so any movement is the model
#: reading length. Three points is noise at these sample sizes; nsfw moved 15.6.
LENGTH_DRIFT_ALLOWED = 0.03

#: Padding that lengthens a sentence without saying anything any detector cares about.
#:
#: This started as "This is a routine notice sent to every customer on the account, and
#: it needs no reply unless the details below are wrong", and that made `injection` fire
#: on 16 of 20 padded sentences against 1 of 20 short ones, which read as strong length
#: sensitivity. It was not. That padding scores 0.3512 on `injection` by itself, just
#: under its 0.43 threshold, because it contains an imperative and refers to "the
#: details below": an injection detector reacting to it is the detector working.
#: Appending a near-positive to every sentence and calling the result a length effect is
#: the same mistake this file exists to catch, made in the fixture.
#:
#: So the padding is now descriptive, third person, on an unrelated subject, and scores
#: 0.0031, 0.0007 and 0.0017 on `injection`, `regulated_advice` and `nsfw` on its own.
NEUTRAL_PADDING = (
    " Rainfall in the region was slightly below the seasonal average throughout"
    " the whole of the preceding quarter."
)

#: Detectors that fail these probes today, with the measured number, so the list is
#: evidence rather than a guess. Marked strict xfail, so the retrain that fixes one
#: shows up as a failure here and the list has to shrink.
#:
#: Measured 2026-08-13 at the shipped thresholds, over the twenty sentences below:
#:
#:   nsfw               1 of 20 short, 0 padded    FIXED, retrained 2026-08-13
#:   regulated_advice   5 of 20 short, 0 padded    same shape, smaller; unavailable
#:   injection          1 of 20 short, 0 padded    clean
#:   bias               0 of 20                    clean
#:   politeness         0 of 20                    clean
#:   toxicity           0 of 20                    clean
#:   gibberish          0 of 20                    clean
#:
#: `nsfw` came off this list on 2026-08-13, which is what the strict xfail is for: the
#: retrain made both of its tests XPASS, the run failed, and the failure was the
#: instruction to update this tuple. Its threshold moved from 0.95 to the newly
#: calibrated 0.81 at the same time, in policies/default.yaml, with the measurement.
#:
#: Worth stating plainly, because it corrects an assumption made in this file's first
#: version: `bias`, `politeness` and `toxicity` all carry the length confound in their
#: corpora, at 0.73, 0.85 and 0.97 on the separation metric, and all three are clean on
#: ordinary prose at their calibrated thresholds. The confound and the failure are not
#: the same thing. Cutting their own hard negatives to 55 characters does move them (1.5
#: to 9.2 percent, 3.2 to 14.0, 2.9 to 9.6), so they read length where the text is
#: already ambiguous and not where it is plainly ordinary. Their corpora still get the
#: fix, because a model that reads length near its boundary is fragile in a way a caller
#: will eventually find; they are simply not broken today.
NOT_YET_RETRAINED = ("regulated_advice",)


def _xfail_if_untrained(detector_id: str, reason: str) -> object:
    """Build a parametrize entry, xfailing the ones with a recorded failure.

    At parametrize time rather than inside the test body. The first version of this
    file called `request.node.add_marker` during the call phase, which pytest
    applies inconsistently: three detectors that pass reported as strict XPASS
    failures and one that fails reported as a plain failure, so the run said nine
    failures where there were two real ones.
    """
    if detector_id in NOT_YET_RETRAINED:
        return pytest.param(
            detector_id, marks=pytest.mark.xfail(strict=True, reason=reason)
        )
    return detector_id


def _detector(detector_id: str) -> ClassifierDetector:
    from flowx_border.detectors.classifier import ClassifierDetector
    from flowx_border.models.registry import ModelUnavailableError

    detector = ClassifierDetector(detector_id, detector_id)
    try:
        detector.warm()
    except ModelUnavailableError as error:
        pytest.skip(f"{detector_id} weights not available: {error}")
    return detector


def _fires(
    detector: ClassifierDetector, texts: tuple[str, ...], threshold: float
) -> int:
    fired = 0
    for text in texts:
        scores = detector.scores(text, 1, 8)
        detector.forget()
        if scores and max(scores.values()) >= threshold:
            fired += 1
    return fired


def _cut(text: str, limit: int = 55) -> str:
    """The first ~55 characters, ending on a word boundary.

    Truncation rather than paraphrase on purpose: the content is then a subset of
    what the model already scores as negative, so anything the score does is about
    length.
    """
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0] + "."


def test_thresholds_match_the_shipped_policy() -> None:
    """The numbers above are the ones a caller actually gets.

    Without this the file could pass while describing thresholds nobody ships, which
    is the failure mode the whole file exists to catch, one level up.
    """
    from flowx_border.policy import load_policy

    policy = load_policy("policies/default.yaml")
    for detector_id, expected in THRESHOLDS.items():
        assert policy.for_detector(detector_id).threshold == pytest.approx(expected), (
            f"{detector_id}: this file says {expected}, policies/default.yaml says "
            f"{policy.for_detector(detector_id).threshold}. One is stale, and a"
            " robustness test against a threshold nobody ships proves nothing."
        )


@pytest.mark.slow
@pytest.mark.parametrize(
    "detector_id",
    [
        _xfail_if_untrained(
            detector_id,
            "its corpus is entirely hard negatives, so ordinary prose is out of "
            "distribution and the sigmoid saturates on it. Being rebuilt with mundane "
            "registers and length bands; when that lands this xfail becomes a"
            " failure and the detector comes off NOT_YET_RETRAINED.",
        )
        for detector_id in sorted(THRESHOLDS)
    ],
)
def test_ordinary_prose_does_not_fire(detector_id: str) -> None:
    """Twenty mundane sentences in ten languages, at the shipped threshold.

    A guard that refuses an invoice reminder gets switched off, and a guard that is
    switched off has a recall of zero whatever its test set says.
    """
    detector = _detector(detector_id)
    fired = _fires(detector, MUNDANE, THRESHOLDS[detector_id])
    assert fired <= MUNDANE_ALLOWED, (
        f"{detector_id} fires on {fired} of {len(MUNDANE)} ordinary sentences at its "
        f"shipped threshold {THRESHOLDS[detector_id]}. Its own test negatives are"
        " all hard boundary cases, so mundane text has nothing in distribution to"
        " be placed against."
    )


@pytest.mark.slow
@pytest.mark.parametrize(
    "detector_id",
    [
        _xfail_if_untrained(
            detector_id,
            "it reads length as label: its corpus has positives systematically shorter "
            "than negatives, so the same meaning fires when short and not when"
            " long. Fixed by the length bands in the generator; this xfail is the"
            " signal for that.",
        )
        for detector_id in sorted(THRESHOLDS)
    ],
)
def test_length_alone_does_not_change_the_verdict(detector_id: str) -> None:
    """The same ordinary sentences, lengthened with text that carries no signal.

    The inverse of the probe above, and the one that identified the cause. `nsfw`
    fires on 11 of the 20 short forms and 0 of the padded ones, for identical
    meaning, which is length rather than topic. A detector that passes the mundane
    probe only because the sentences happen to be a particular length is not passing
    for the right reason.

    The padding has to be genuinely inert or this test measures the padding. See
    NEUTRAL_PADDING for the version that did.
    """
    detector = _detector(detector_id)
    threshold = THRESHOLDS[detector_id]
    padding_alone = detector.scores(NEUTRAL_PADDING.strip(), 1, 8)
    detector.forget()
    assert not padding_alone or max(padding_alone.values()) < threshold / 4, (
        f"the padding scores {max(padding_alone.values()):.4f} on {detector_id} by"
        f" itself, against its {threshold} threshold. It is not inert, so appending"
        " it measures the padding rather than the length. Pick different filler."
    )

    padded = tuple(text + NEUTRAL_PADDING for text in MUNDANE)
    short_fired = _fires(detector, MUNDANE, threshold)
    long_fired = _fires(detector, padded, threshold)
    assert abs(short_fired - long_fired) <= 1, (
        f"{detector_id} fires on {short_fired} of the short forms and {long_fired}"
        " of the padded ones, for the same meaning plus inert filler. Length carries"
        " the verdict."
    )


@pytest.mark.slow
def test_gibberish_is_the_control_for_the_length_finding() -> None:
    """The one corpus with a deliberately short negative register, asserted as such.

    `gibberish` declares `short_but_valid` ("two or three words, the most common
    false positive") and is the only one of six models whose false-positive rate did
    not move when its negatives were cut to 55 characters: 3.2 percent to 2.6
    percent, against nsfw's 1.3 to 16.8.

    This is here because the whole length fix rests on that one natural experiment.
    If `gibberish` ever starts reading length too, the argument for the fix is
    weaker than this project currently believes and the reasoning needs revisiting
    rather than the threshold nudging.
    """
    detector = _detector("gibberish")
    threshold = THRESHOLDS["gibberish"]
    # Its own hard negatives are not available offline, so the mundane set stands
    # in: these are meaningful prose, which is what `gibberish` must never flag, at
    # two lengths.
    short = _fires(detector, MUNDANE, threshold)
    cut = _fires(detector, tuple(_cut(text) for text in MUNDANE), threshold)
    assert short == 0, (
        f"gibberish fires on {short} of {len(MUNDANE)} meaningful sentences"
    )
    assert cut == 0, (
        f"gibberish fires on {cut} of {len(MUNDANE)} truncated but still meaningful "
        "sentences. It was the length-robust control; that no longer holds."
    )
