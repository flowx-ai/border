# SPDX-License-Identifier: Apache-2.0
"""Collect every number this project is allowed to publish, into one file.

    uv run python benchmarks/collect.py --artifacts ~/Dev/assay/training/artifacts_local

Writes `docs/reference/performance.json` and `docs/reference/performance.md`.

Why this exists
---------------

CLAUDE.md's rule is that a number in the README must have a benchmark in the repo that
produces it. Until now the numbers lived in commit messages and conversation, which is
the one place they cannot be checked from.

There is a second consumer. The landing page reads the model list and the per-model
performance, and the failure mode there is worse than a stale README: a marketing page
saying `toxicity: F1 1.000 (Danish)` when that figure rests on four test examples. So
the JSON is shaped to make that hard to do by accident.

The three rules the shape enforces
----------------------------------

**No score without its support.** Every metric object carries `n`. A renderer that wants
a number has the sample size in the same object, so omitting it is a choice rather than
an oversight, and `tests/test_performance.py` fails if any metric lacks one.

**No number for a detector that is not built.** Status comes from the registry at
collection time. A detector whose weights are absent gets `"metrics": null` and a
reason, rather than last week's figures, because a page claiming a check runs when it
does not is the failure this project refuses everywhere.

**Caveats travel with the data, not in a footnote.** `caveats` is a list of sentences on
the detector itself. A language with fewer than ten test examples says so, and a score
of zero says what is known about why, without inventing a cause: the one zero this file
was written around turned out to be a sample size of two rather than the base model
everyone assumed.

Latency is measured here, live, at the reference input from `tests/test_budgets.py`, so
the figure and the assertion cannot drift apart.
"""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
OUT_JSON = REPO / "docs" / "reference" / "performance.json"
OUT_MD = REPO / "docs" / "reference" / "performance.md"

#: Below this many test examples, a per-language score is reported with a warning
#: attached. Ten is not a statistical threshold, it is the point below which a single
#: example moves the number by ten percentage points or more, which is enough to mislead
#: a reader.
THIN_SUPPORT = 10

#: Absent from XLM-RoBERTa's pretraining corpus, which is a fact about the base model
#: and worth attaching to a score from it.
#: What it is NOT is an explanation for a low score, and this file said it was until
#: 2026-08-11. nsfw scored 0.000 in Maltese and the caveat read "which no data fixes".
#: Then the corpus went from 2 positives per language to 10 and Maltese scored 1.000,
#: precision and recall both perfect. The 0.000 was the sample size the whole time. So
#: the note now states the fact and stops there: a reader can weigh it, and nobody is
#: told a number is unfixable when it was only unmeasured.
NOT_IN_BASE_MODEL = {"mt"}

LANGUAGE_NAMES = {
    "bg": "Bulgarian",
    "cs": "Czech",
    "da": "Danish",
    "de": "German",
    "el": "Greek",
    "en": "English",
    "es": "Spanish",
    "et": "Estonian",
    "fi": "Finnish",
    "fr": "French",
    "ga": "Irish",
    "hr": "Croatian",
    "hu": "Hungarian",
    "it": "Italian",
    "lt": "Lithuanian",
    "lv": "Latvian",
    "mt": "Maltese",
    "nl": "Dutch",
    "pl": "Polish",
    "pt": "Portuguese",
    "ro": "Romanian",
    "sk": "Slovak",
    "sl": "Slovenian",
    "sv": "Swedish",
    "tr": "Turkish",
    "az": "Azerbaijani",
}


def _artifact_dir(root: Path, detector: str) -> Path | None:
    """The artifact folder for a detector, in either naming convention."""
    for name in (f"{detector}-full", detector, detector.replace("_", "") + "-full"):
        if (root / name).is_dir():
            return root / name
    return None


def _read_eval(folder: Path, detector: str) -> dict[str, Any] | None:
    for candidate in (
        f"{detector}_eval.json",
        f"{detector.replace('_', '')}_eval.json",
    ):
        path = folder / candidate
        if path.exists():
            loaded: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
            return loaded
    return None


def _shape_of(per_language: dict[str, Any]) -> tuple[str, str, str]:
    """Which metric this evaluation can honestly report, and what its count means.

    Three shapes exist in the artifacts, and conflating them is how a misleading number
    gets published:

    **Multi-label**, a threshold head: carries `f1` and `support`, where `support` is
    the number of *positive* examples for that language. F1 rests on those positives, so
    they are the count to quote. Some of these also carry `n`, the total evaluated,
    which is a different and larger number.

    **Single-label**, an argmax head: carries `accuracy` and `n`, with `support` often 0
    because there is no positive class. P/R/F1 over "did it fire" is 1.000 by
    construction here, which is why the trainer refuses to print it and why this reads
    accuracy.

    **A bare float**, which is `topic_scope`: per-language top-1 accuracy with no count
    recorded anywhere in the file. That one cannot be given a sample size without
    inventing one, so it gets `n: null` and says so.

    Returns (metric, score_key, count_meaning).
    """
    rows = list(per_language.values())
    if all(isinstance(row, int | float) for row in rows):
        return "top1_accuracy", "", "not recorded"

    has_f1 = any(isinstance(row, dict) and row.get("f1", 0.0) > 0.0 for row in rows)
    if has_f1:
        return "f1", "f1", "positive examples"
    return "exact_match_accuracy", "accuracy", "examples evaluated"


def quality_for(root: Path, detector: str) -> dict[str, Any] | None:
    """Per-language numbers for one detector, or None when there is no evaluation."""
    folder = _artifact_dir(root, detector)
    if folder is None:
        return None
    evaluation = _read_eval(folder, detector)
    if evaluation is None:
        return None

    per_language = evaluation.get("per_language") or {}
    if not per_language:
        return None

    metric, score_key, count_means = _shape_of(per_language)

    languages: dict[str, Any] = {}
    for code, row in sorted(per_language.items()):
        notes = []
        count: int | None
        if isinstance(row, int | float):
            score = float(row)
            count = None
            notes.append(
                "the evaluation did not record how many examples this rests on, so the "
                "score is unverifiable rather than measured"
            )
        else:
            score = float(row.get(score_key, 0.0))
            if count_means == "positive examples":
                count = int(row.get("support") or 0)
            else:
                count = int(row.get("n") or 0)
            if count < THIN_SUPPORT:
                notes.append(
                    f"only {count} {count_means}, so one case moves this materially"
                )
        entry: dict[str, Any] = {"score": round(score, 4), "n": count}
        # The total evaluated, where the file records both. Kept distinct from `n`
        # because a reader told "5 examples" when 5 was the positive count inside a set
        # of 40 has been given the wrong number, not a rounded one.
        both_counts = count_means == "positive examples" and isinstance(row, dict)
        if both_counts and row.get("n"):
            entry["n_evaluated"] = int(row["n"])
        if code in NOT_IN_BASE_MODEL:
            notes.append(
                "absent from the base model's pretraining corpus, which is worth "
                "knowing but has not been shown to bound the score: nsfw went from "
                "0.000 to 1.000 here on more examples"
            )
        if notes:
            entry["notes"] = notes
        languages[code] = entry

    scores = [entry["score"] for entry in languages.values()]
    calibration = folder / "calibration.json"
    threshold = None
    objective = None
    if calibration.exists():
        loaded = json.loads(calibration.read_text(encoding="utf-8"))
        threshold, objective = loaded.get("threshold"), loaded.get("objective")

    counted = [e["n"] for e in languages.values() if e["n"] is not None]
    out: dict[str, Any] = {
        "metric": metric,
        "n_means": count_means,
        "macro": round(sum(scores) / len(scores), 4),
        "median": round(statistics.median(scores), 4),
        "worst": round(min(scores), 4),
        "best": round(max(scores), 4),
        "languages_evaluated": len(languages),
        # None rather than 0 when no language recorded a count. A zero here would read
        # as "measured on nothing", which is a claim; None is the absence of one.
        "total_examples": sum(counted) if counted else None,
        "languages_without_a_count": sorted(
            code for code, e in languages.items() if e["n"] is None
        ),
        "per_language": languages,
        "threshold": threshold,
        "threshold_chosen_by": objective,
    }
    if evaluation.get("pair_accuracy") is not None:
        out["headline"] = {
            "name": "pair_accuracy",
            "value": round(float(evaluation["pair_accuracy"]), 4),
            "means": "both halves of a minimal pair correct",
        }
    return out


def caveats_for(quality: dict[str, Any] | None) -> list[str]:
    """Sentences that must travel with the numbers rather than sit in a footnote."""
    if quality is None:
        return []
    notes = []
    uncounted = quality["languages_without_a_count"]
    if uncounted:
        notes.append(
            f"the evaluation recorded no sample size for {len(uncounted)} of "
            f"{quality['languages_evaluated']} languages, so those scores cannot be "
            "checked for how much they rest on. Treat them as unverified."
        )
    thin = [
        c
        for c, e in quality["per_language"].items()
        if e["n"] is not None and e["n"] < THIN_SUPPORT
    ]
    if thin:
        notes.append(
            f"{len(thin)} of {quality['languages_evaluated']} languages have fewer "
            f"than {THIN_SUPPORT} {quality['n_means']}: {', '.join(sorted(thin))}. "
            "Their individual scores are indicative rather than measured."
        )
    zeroes = [c for c, e in quality["per_language"].items() if e["score"] == 0.0]
    if zeroes:
        base = sorted(set(zeroes) & NOT_IN_BASE_MODEL)
        rest = sorted(set(zeroes) - NOT_IN_BASE_MODEL)
        if base:
            notes.append(
                f"scores zero in {', '.join(base)}, which is absent from "
                "XLM-RoBERTa's pretraining. Check the sample size before blaming "
                "the base model: the one time this was investigated, it was not "
                "the cause."
            )
        if rest:
            notes.append(
                f"scores zero in {', '.join(rest)}, which is unexplained and a bug "
                "to chase."
            )
    if quality.get("threshold") is None:
        notes.append(
            "no calibrated threshold recorded, so this detector runs at the policy "
            "default. Several detectors in this family reported nothing at 0.5 while "
            "separating positives from negatives well below it."
        )
    return notes


def latency_for(detectors: dict[str, Any]) -> dict[str, Any]:
    """Measure every loaded detector at the reference input, once, here.

    Imported from the budget tests rather than restated, so the published figure and the
    asserted ceiling describe the same string.
    """
    import sys

    sys.path.insert(0, str(REPO / "tests"))
    from flowx_border.detectors.base import Context, DetectorConfig
    from test_budgets import REFERENCE_INPUT  # type: ignore[import-not-found]

    ctx = Context(sources=("a source passage",))

    # A detector that needs policy data returns early without it, and publishing that
    # early return as its latency would be a figure for the path nobody runs.
    # topic_scope measured 0.06 ms this way, against 30 ms configured. Representative
    # options are supplied here for the detectors that need them, and anything still
    # taking the unconfigured path is labelled below rather than reported as fast.
    representative = {
        "topic_scope": {
            "taxonomy": {
                "allowed": [
                    {
                        "path": "banking/accounts",
                        "description": "accounts, balances, statements and transfers",
                    }
                ],
                "disallowed": [
                    {
                        "path": "banking/crypto",
                        "description": "cryptocurrency and token speculation",
                    },
                    {
                        "path": "health/medical",
                        "description": "symptoms, diagnosis and treatment",
                    },
                ],
            }
        },
        "banned_terms": {"terms": ["parola", "kennwort", "sifre"]},
        "internal_domains": {"domains": ["internal.example", "corp.example"]},
    }

    #: A finding label ending in one of these means the detector reported that it could
    #: not do its job, so the timing describes the refusal rather than the work. Matched
    #: by suffix rather than by detector id, so a new detector reporting the same way is
    #: covered without the collector knowing about it.
    did_not_run = ("_unconfigured", "_unverifiable", "_no_claims")
    out: dict[str, Any] = {
        "reference_input": {
            "characters": len(REFERENCE_INPUT),
            "description": "Romanian prose with no entities in it, so this measures "
            "the cost of looking rather than the cost of finding",
        },
        "threads": 1,
        "provider": "CPUExecutionProvider",
        "per_detector_ms": {},
    }
    # One estimator, imported rather than restated, so the published figure and the
    # asserted ceiling are computed the same way. It warms outside the timed region and
    # takes the best of several rounds; measuring here with neither put the 437 ms
    # tokenizer load inside the first sample and, with twelve samples, the p95 index
    # landed exactly on it. That is how the classifiers came to be published at 362 ms
    # when they cost 151.
    from test_budgets import p95  # type: ignore[import-not-found]

    for name, detector in sorted(detectors.items()):
        try:
            detector.warm()
        except Exception as error:
            out["per_detector_ms"][name] = {"error": str(error)[:120]}
            continue

        entry_cfg = DetectorConfig(on_fail="flag", options=representative.get(name, {}))
        forget = getattr(detector, "forget", None)
        before = forget if callable(forget) else None

        produced = detector.run(REFERENCE_INPUT, entry_cfg, ctx)
        refused = [
            f.label
            for f in produced
            if any(f.label.endswith(suffix) for suffix in did_not_run)
        ]

        measured = p95(
            lambda d=detector, c=entry_cfg: d.run(REFERENCE_INPUT, c, ctx),
            12,
            before,
        )
        record: dict[str, Any] = {"p95": round(measured, 3)}
        if refused:
            record["describes"] = (
                f"the path where the detector reported {refused[0]} rather than "
                "the path where it does its work, because the reference "
                "configuration does not give it what it needs"
            )
        out["per_detector_ms"][name] = record
    return out


def collect(artifacts: Path | None) -> dict[str, Any]:
    from flowx_border.detectors.catalogue import CATALOGUE, CORE, REQUIREMENTS
    from flowx_border.registry import loaded_detectors

    loaded = dict(loaded_detectors())
    detectors: dict[str, Any] = {}

    for detector_id, spec in sorted(CATALOGUE.items()):
        built = detector_id in loaded
        quality = quality_for(artifacts, detector_id) if (artifacts and built) else None
        detectors[detector_id] = {
            "tier": spec.tier,
            "sides": sorted(spec.sides),
            "budget_ms": spec.budget_ms,
            "in_core": detector_id in CORE,
            "requires": {
                need: REQUIREMENTS.get(need, "") for need in sorted(spec.requires)
            },
            "status": "built" if built else "not built",
            "metrics": quality,
            "caveats": caveats_for(quality),
        }
        if not built:
            detectors[detector_id]["why_not_built"] = (
                "weights are not published yet and no local override provides them"
            )
        elif quality is None:
            detectors[detector_id]["metrics_note"] = (
                "no evaluation artifact was available at collection time. A "
                "rules-based detector has none by nature; a model-backed one "
                "missing this is a gap."
            )

    return {
        "generated_by": "benchmarks/collect.py",
        "reading_this": (
            "Every score carries its sample size in `n`. A detector that is not "
            "built has `metrics: null` rather than stale figures. `caveats` is not "
            "optional reading: it is where a score of 1.000 on four examples says so."
        ),
        "artifacts_read_from": str(artifacts) if artifacts else None,
        "detectors": detectors,
        "latency": latency_for(loaded),
    }


def to_markdown(data: dict[str, Any]) -> str:
    lines = [
        "# Measured performance",
        "",
        "Generated by `benchmarks/collect.py`. Do not edit:",
        "`tests/test_performance.py` fails if this disagrees with the JSON beside it.",
        "",
        "Every score below carries the number of examples behind it, and the `n means`",
        "column says what those examples are. A count of positives is not a count",
        "of everything evaluated, and the two are not interchangeable. Where the",
        "evaluation recorded no count at all the cell reads `not recorded`, which",
        "means the score is unverified rather than good or bad.",
        "",
        "## Detectors",
        "",
        "| Detector | Tier | Status | Metric | Macro | Median | Worst "
        "| Test cases | n means |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for name, entry in data["detectors"].items():
        metrics = entry["metrics"]
        if metrics is None:
            lines.append(
                f"| `{name}` | {entry['tier']} | {entry['status']} "
                "| – | – | – | – | – | – |"
            )
            continue
        total = metrics["total_examples"]
        lines.append(
            f"| `{name}` | {entry['tier']} | {entry['status']} | {metrics['metric']} "
            f"| {metrics['macro']:.3f} | {metrics['median']:.3f} "
            f"| {metrics['worst']:.3f} "
            f"| {total if total is not None else 'not recorded'} "
            f"| {metrics['n_means']} |"
        )

    lines += ["", "## Caveats", ""]
    any_caveat = False
    for name, entry in data["detectors"].items():
        for caveat in entry["caveats"]:
            lines.append(f"- **`{name}`**: {caveat}")
            any_caveat = True
    if not any_caveat:
        lines.append(
            "None recorded, which for a project at this stage is itself suspicious."
        )

    latency = data["latency"]
    lines += [
        "",
        "## Latency",
        "",
        f"At a {latency['reference_input']['characters']} character reference input, "
        f"{latency['threads']} thread, {latency['provider']}. "
        f"{latency['reference_input']['description']}.",
        "",
        "| Detector | p95 ms | Budget ms | note |",
        "|---|---|---|---|",
    ]
    for name, timing in sorted(latency["per_detector_ms"].items()):
        budget = data["detectors"].get(name, {}).get("budget_ms", "–")
        if "error" in timing:
            lines.append(f"| `{name}` | – | {budget} | weights unavailable |")
            continue
        note = "the unconfigured path" if "describes" in timing else "–"
        lines.append(f"| `{name}` | {timing['p95']:.3f} | {budget} | {note} |")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--artifacts",
        type=Path,
        default=None,
        help=(
            "a directory of artifact folders holding the evaluation JSON. Without "
            "it, latency is still measured and quality is reported as unavailable "
            "rather than guessed."
        ),
    )
    args = parser.parse_args()

    artifacts = args.artifacts.expanduser() if args.artifacts else None
    if artifacts is not None and not artifacts.is_dir():
        raise SystemExit(f"{artifacts} is not a directory")

    data = collect(artifacts)
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    OUT_MD.write_text(to_markdown(data), encoding="utf-8")

    built = sum(1 for e in data["detectors"].values() if e["status"] == "built")
    scored = sum(1 for e in data["detectors"].values() if e["metrics"] is not None)
    print(f"wrote {OUT_JSON.relative_to(REPO)} and {OUT_MD.relative_to(REPO)}")
    total = len(data["detectors"])
    caveats = sum(len(e["caveats"]) for e in data["detectors"].values())
    print(f"  {total} catalogued, {built} built, {scored} with measured quality")
    print(f"  {caveats} caveats recorded")


if __name__ == "__main__":
    main()
