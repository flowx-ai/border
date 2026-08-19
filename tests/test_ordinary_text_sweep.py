# SPDX-License-Identifier: Apache-2.0
"""Every detector, over ordinary text, in all 26 languages.

**This is the shape of check that has caught every serious false positive in this
project, and each time it caught one no unit test was failing.**

- `nsfw` shipped `on_fail: block` and fired on 55 percent of mundane business prose. Its
  macro F1 was 0.976, its per-language false positive rate 0.0, and both were measured
  against hard negatives that were all long and topic-adjacent. Ordinary text was
  nowhere in the corpus, so the sigmoid had nothing to place it against.
- `injection` called "The balance was 1234.56 before rounding" an attack at 0.9697. Its
  eval said 0.9685 macro.
- `pii` redacted `Friday` and `Maerz` as people.

None of those is visible from a corpus score, because every corpus scores a detector
against its own negatives and none of them contains a delivery note. This file is the
opposite: it asks what the whole shipped configuration does to text nobody would think
twice about.

## What counts as a failure

Firing is not automatically wrong. A `disclosure` finding on text with no disclosure is
the policy working, and detectors that report `_unconfigured` or `_unverifiable` are
obeying the rule that a detector never silently does nothing. So the sweep asserts
on the two things that are unambiguously bad:

**Nothing may block or redact ordinary text.** A `block` on a parcel-tracking
sentence is a refused answer; a `redact` is text removed from a caller's output. Both
are visible damage and neither is recoverable by the caller.

**No detector may fire above a rate that its own history says is wrong.** The
per-detector ceilings below are set from measurement, not taste, and a detector that
crosses one has regressed into the failure mode that produced its ceiling.

## Where the text comes from

Two sources, deliberately.

`data/moderation_train.jsonl`'s three `mundane_*` registers, 4,981 rows over 26
languages with no label at all. Generated, so they share a generator with the corpora
the detectors trained on, which is a real limit: a detector could in principle be blind
to exactly this model's idea of ordinary text.

So also the 26 hand-written sentences from `test_language_id.py`, which no generator
produced. If the two sources ever disagree, the hand-written ones are the evidence.
"""

from __future__ import annotations

import collections
import json
import os
from pathlib import Path

import pytest

os.environ.setdefault("HF_HUB_OFFLINE", "1")

from flowx_border import load_policy, scan_input, scan_output
from flowx_border.registry import DetectorUnavailableError
from test_language_id import SENTENCES

pytestmark = pytest.mark.slow

CORPUS = (
    Path(__file__).resolve().parent.parent.parent
    / "training"
    / "data"
    / "moderation_train.jsonl"
)
POLICY = Path(__file__).resolve().parent.parent / "policies" / "default.yaml"

#: Rows per language from the corpus. Small enough to run in the suite, large enough
#: that a 5 percent fire rate is three or four rows rather than noise.
PER_LANGUAGE = 8

#: How often a detector may fire on ordinary text before it has regressed.
#:
#: Every number here is a measurement rather than a preference. The four classifiers
#: that were retrained on corpora carrying mundane registers measured 0 of 20 at three
#: thresholds each, so their ceiling is low and deliberately not zero: one genuinely
#: ambiguous sentence somebody adds to the corpus should not fail the suite.
#:
#: Detectors absent from this table may fire freely, because firing is what they are for
#: on this text: `disclosure` reports a missing disclosure on every row, and the
#: `_unconfigured` family reports that a policy gave them nothing to check.
MAX_FIRE_RATE: dict[str, float] = {
    "nsfw": 0.05,
    "toxicity": 0.05,
    "bias": 0.05,
    "politeness": 0.05,
    "gibberish": 0.05,
    "injection": 0.05,
    "output_leakage": 0.25,
    "language_id": 1.0,
}

#: The two that are over their ceiling today, split out so the eight above stay
#: enforced. A single xfail covering the whole table would mean a regression in
#: `toxicity` no longer failed anything, which is how a known failure becomes cover for
#: an unknown one.
#:
#: The ceilings here are where each should be, not where it is. Measured values are in
#: the xfail reason on the test that carries them.
KNOWN_OVER: dict[str, float] = {
    "pii": 0.25,
    "regulated_advice": 0.10,
}

#: Labels that are a detector reporting it could not run, rather than a finding about
#: the text. These are the third rule working and are counted separately.
#: The label the engine records when a detector raises under `fail_mode: open`.
#: Not in NON_FINDING on purpose: it must stop the sweep rather than be filtered
#: out of it, because a sweep missing a detector is not a smaller sweep.
DETECTOR_ERROR = "detector_error"

NON_FINDING = (
    "_unconfigured",
    "_unverifiable",
    "_no_source",
    "unknown",
    "uncertain",
)


def ordinary_rows() -> list[tuple[str, str]]:
    """(language, text) for ordinary text, corpus first then the hand-written set.

    Stratified by register within each language, and that is not a refinement.

    This took `texts[:PER_LANGUAGE]` until 2026-08-19, the first rows per language in
    corpus order. When `mundane_account_access` was added as a fourth mundane register
    the corpus began writing it first, so all 208 corpus rows became account-access
    requests and the sweep stopped measuring ordinary text at all: one register only.

    What that produced looked exactly like a regression: `regulated_advice` fired on
    0.829 of rows against a 0.10 ceiling and `bias` on 0.068 against 0.05, with no code
    change and no model change. The rows had changed underneath it. So a sample built by
    slicing corpus order is a sample that moves when a generator's register order does,
    and the number it produces is not comparable with the one before it.
    """
    out: list[tuple[str, str]] = []
    if CORPUS.exists():
        by_cell: dict[tuple[str, str], list[str]] = collections.defaultdict(list)
        for line in CORPUS.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            register = str(row.get("register", ""))
            if register.startswith("mundane") and not row.get("labels"):
                by_cell[(row["language"], register)].append(row["text"])
        languages = sorted({language for language, _ in by_cell})
        for language in languages:
            registers = sorted(r for lang, r in by_cell if lang == language)
            if not registers:
                continue
            # Round robin, so every register contributes and the count per language is
            # unchanged whatever order the corpus was written in.
            share, extra = divmod(PER_LANGUAGE, len(registers))
            for index, register in enumerate(registers):
                take = share + (1 if index < extra else 0)
                out += [
                    (language, text) for text in by_cell[(language, register)][:take]
                ]
    out += list(SENTENCES.items())
    return out


def is_non_finding(label: str) -> bool:
    return any(marker in label for marker in NON_FINDING)


@pytest.fixture(scope="module")
def sweep() -> dict[str, object]:
    """Run every detector over every ordinary row, both sides, once."""
    rows = ordinary_rows()
    if len(rows) < 100:
        pytest.skip(
            f"only {len(rows)} ordinary rows available, which is too few to measure a "
            "rate. The corpus lives in the training repository."
        )
    policy = load_policy(str(POLICY))

    # A sweep that ran with half the detectors missing would report a clean result and
    # mean nothing by it, and the strict xfail below would then pass for the wrong
    # reason. Skipping is the honest outcome: the point of this file is what the whole
    # shipped configuration does, so a partial configuration is not a smaller version of
    # it. Every model-backed detector is held back until release, so a fresh clone lands
    # here and is told what to set rather than left with a green run.
    probe = "A parcel was delivered to the office this morning."
    try:
        scan_output(probe, policy)
    except DetectorUnavailableError as unavailable:
        pytest.skip(
            f"the default policy needs detectors this install cannot provide, so the "
            f"sweep would measure a subset and report it as the whole: {unavailable}. "
            "Point FLOWX_BORDER_MODEL_DIR at the artifact directory to run it."
        )

    # A detector that raised from `warm` does not reach the check above, because T1 and
    # T2
    # are `fail_mode: open` and the engine records the failure as a finding instead of
    # letting it propagate. That finding then counts as a fire on every row, and the
    # ceiling assertion reports it as a false positive rate of 1.000.
    #
    # Which is how "injection fires on 100 percent of ordinary text" was really "the
    # registry pin moved ahead of the local model cache", on 2026-08-18. A load failure
    # reported as a perfect false positive rate is worse than a crash: it names the
    # wrong
    # cause and the number looks like a measurement.
    #
    # Both sides, because a detector can be input-only: `injection` is, and the original
    # probe only scanned output, so it saw nothing wrong.
    broken = sorted(
        {
            finding.detector_id
            for scan in (scan_input, scan_output)
            for finding in scan(probe, policy).findings
            if finding.label == DETECTOR_ERROR
        }
    )
    if broken:
        pytest.skip(
            f"these detectors could not run and the engine recorded {DETECTOR_ERROR!r} "
            f"for them: {', '.join(broken)}. The sweep would count that as firing on "
            "every row. Usually the registry pins a revision this machine has not "
            "fetched, so run a scan once with network access, or point "
            "FLOWX_BORDER_MODEL_DIR at the artifact directory."
        )

    # Counted per row, not per finding. A product description naming four entities is
    # one over-redacted row, and dividing findings by rows produced a "rate" of 3.62
    # which is not a rate at all.
    fired: collections.Counter[str] = collections.Counter()
    damaged: collections.Counter[str] = collections.Counter()
    damaging: list[tuple[str, str, str, str]] = []
    seen = 0
    for language, text in rows:
        seen += 1
        hit: set[str] = set()
        hurt: set[str] = set()
        for scan in (scan_input, scan_output):
            decision = scan(text, policy)
            for finding in decision.findings:
                if is_non_finding(finding.label):
                    continue
                hit.add(finding.detector_id)
                if finding.action in ("block", "redact"):
                    hurt.add(finding.detector_id)
                    fragment = (
                        text[finding.span[0] : finding.span[1]] if finding.span else ""
                    )
                    damaging.append(
                        (finding.detector_id, finding.label, language, fragment)
                    )
        for detector in hit:
            fired[detector] += 1
        for detector in hurt:
            damaged[detector] += 1
    return {"rows": seen, "fired": fired, "damaged": damaged, "damaging": damaging}


@pytest.mark.xfail(
    reason=(
        "Measured over 234 ordinary rows in 26 languages. This read 0.756 of rows "
        "losing text on 2026-08-16 and reads 0.162 after three changes the same day: "
        "`date` moved to `flag` in the default policy, `iban` got the ISO 13616 length "
        "floor, and the piiguard artifact was swapped for the retrain that fixes DATE "
        "and NATIONAL_ID.\n\n"
        "**The artifact swap was most of it, and that is the part worth reading.** "
        "`person` went 0.581 to 0.128 and `national_id` 0.064 to 0.017 with no library "
        "change at all. The first version of this xfail concluded that `person` needed "
        "a corpus fix and a retrain; the retrain already existed, in a sibling "
        "directory on the same disk, and scored 0.128. Compare the reports before "
        "concluding anything about a model.\n\n"
        "**0.162 to 0.0940 on 2026-08-19, from a per-entity bar on `person`.** The "
        "residue was place names, and reading the sweep said why: `person` is the one "
        "type with no shape to check, so an unfamiliar capitalised token mid-sentence "
        "lands there and `entity_shapes.py` has nothing to reject it with. An ablation "
        "inside fixed frames separated the variables: `Berlin`, `Paris` and `Siemens` "
        "are never tagged, `Regensburg` and `Valletta` are, and an invented "
        "`Grelmshof` scores 0.97, so it is unfamiliarity and not knowledge of place "
        "names. Sentence-initial is exempt, capitalisation there being orthography.\n\n"
        "`options.entity_thresholds` puts a 0.90 bar on `person`, removing 30 of the "
        "43, and 0.90 bars on `national_id` and `phone` too. Held-out recall is 1.0000 "
        "for PERSON over 668 gold spans and for PHONE, and national_id recall is flat "
        "at every bar because its distribution is bimodal. 0 of 560 PERSON spans "
        "survive verbatim in the output. 0.95 was rejected: it removes three more and "
        "loses a Greek honorific at 0.9118, and a missed person is a hole where a "
        "redacted place is visible.\n\n"
        "That reverses the earlier conclusion that a threshold could not help, which "
        "rested on the false positives scoring a median of 0.9416. That figure was "
        "measured on the superseded artifact and asserted to still hold rather than "
        "re-taken; on the adopted model the median is 0.7392.\n\n"
        "What is left, counted rather than characterised. Of 21 surviving spans, 5 are "
        "places named after people where the span does contain a real name (`Franjo "
        "Tudman`, `Deak Ferenc`), 7 are plain toponyms, 4 are `phone` on published "
        "business support lines, and 4 are `national_id` on things that are not "
        "identifiers at all: `EP2237/10` is a Philips model number, `LV-EWT2026` a "
        "kettle. An earlier version of this note said most were places named after "
        "people, which was an impression and not a count. Still damage: a caller who "
        "asked for ordinary prose back does not get it.\n\n"
        "Strict, so whoever fixes it is told rather than left to notice."
    ),
    strict=True,
)
def test_nothing_blocks_or_redacts_ordinary_text(sweep: dict[str, object]) -> None:
    """The failure that would reach a caller as a refused answer or missing text.

    nsfw once blocked one ordinary Spanish sentence about a parcel arriving at an
    office, and that was the residue after a retrain took it from eleven of twenty. A
    single row here is worth reading rather than tolerating.
    """
    damaging = sweep["damaging"]
    assert isinstance(damaging, list)
    report = "\n".join(
        f"  {detector}:{label} [{language}] {text}"
        for detector, label, language, text in damaging[:25]
    )
    assert not damaging, (
        f"{len(damaging)} block/redact findings on ordinary text:\n{report}"
    )


def over_ceiling(sweep: dict[str, object], ceilings: dict[str, float]) -> list[str]:
    fired = sweep["fired"]
    rows = sweep["rows"]
    assert isinstance(fired, collections.Counter)
    assert isinstance(rows, int)
    return [
        f"  {detector}: {fired[detector] / rows:.3f} fired, ceiling {ceiling}"
        for detector, ceiling in sorted(ceilings.items())
        if fired[detector] / rows > ceiling
    ]


def test_no_detector_fires_above_its_measured_ceiling(sweep: dict[str, object]) -> None:
    """A rate check, because one odd sentence is not a regression and a pattern is.

    This one enforces. The eight detectors in MAX_FIRE_RATE are at or under their
    ceilings on ordinary text today, so anything here failing is new.
    """
    over = over_ceiling(sweep, MAX_FIRE_RATE)
    assert not over, (
        "detectors firing on ordinary text above their ceiling:\n" + "\n".join(over)
    )


@pytest.mark.xfail(
    reason=(
        "Measured over the same 234 rows. pii fires on ordinary text above its 0.25 "
        "ceiling and regulated_advice on 0.145 against 0.10.\n\n"
        "pii's firing rate is deliberately not the same question as its damage rate, "
        "which is 0.0769. A date is found and recorded; it is no longer cut "
        "out of the caller's text. This test measures noise in the evidence record and "
        "the one above measures damage to the caller's text.\n\n"
        "The gap widened on 2026-08-19 and the reason is the mechanism working. Of "
        "pii's findings over these rows, 86 are `date` at `flag` by policy, 60 are "
        "`pii_below_entity_threshold_person` at `log`, and only 42 are redactions. The "
        "`person` bar records what it drops rather than removing it silently, so "
        "closing the damage did not close the firing, and it should not: a policy that "
        "raises a bar has to be able to see what the bar dropped.\n\n"
        "regulated_advice is the milder of the two and was already on the known-false-"
        "positive list: it flags rather than redacts, so the cost is a noisy record "
        "rather than damaged text. pii is the one that matters, and the test above "
        "this carries the detail.\n\n"
        "Split from the enforcing test on purpose. Folding these two into one xfail "
        "over the whole table would stop a toxicity or nsfw regression failing "
        "anything, which is a known failure being used as cover for an unknown one."
    ),
    strict=True,
)
def test_the_two_detectors_known_to_be_over_their_ceiling(
    sweep: dict[str, object],
) -> None:
    """Pinned so a corpus fix turns into a failing test rather than into silence."""
    over = over_ceiling(sweep, KNOWN_OVER)
    assert not over, "still over ceiling:\n" + "\n".join(over)


def test_the_sweep_actually_covers_every_language(sweep: dict[str, object]) -> None:
    """A sweep that quietly ran on English only would pass everything above.

    The failure this guards is the one CONTRIBUTING.md names: English plus five is a
    bug. If
    the corpus moves or its registers are renamed, this fails rather than the suite
    silently narrowing to the 26 hand-written sentences.
    """
    rows = ordinary_rows()
    languages = {language for language, _ in rows}
    assert len(languages) == 26, f"swept {len(languages)} languages, not 26"
    assert sweep["rows"] == len(rows)
