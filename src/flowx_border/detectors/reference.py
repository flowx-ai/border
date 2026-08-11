# SPDX-License-Identifier: Apache-2.0
"""The detector reference, rendered from the code that decides it.

Exists because a description of this library written by hand goes out of date the day
after it is written, and the place it goes out of date is the place that matters: which
detectors actually run. `docs/detectors.md` is generated from here, and
`tests/test_reference.py` fails if the two disagree, so anyone describing the library
externally has one source that cannot quietly drift from the catalogue.

**Status is derived, not declared.** Whether a detector is built is read from the
registry at call time rather than from a list somebody maintains. A detector that stops
loading changes this document on the next render, which is the whole point: the failure
being prevented is a page that says a check runs when it does not.

The one thing that has to be maintained by hand is `SUMMARIES`, one line per detector,
because a sentence a non-engineer can read is not derivable from code. A detector in the
catalogue with no summary fails a test rather than rendering blank.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Final, NamedTuple

from flowx_border.detectors.catalogue import CATALOGUE, CORE, REQUIREMENTS

#: Why a catalogued detector is not loaded. Absent means it is.
#:
#: These are the states CLAUDE.md's table records, kept here in the vocabulary an
#: outside reader needs rather than the one the build plan uses.
NOT_BUILT: Final[MappingProxyType[str, str]] = MappingProxyType(
    {
        "injection": "no model published yet",
        "regulated_advice": "no model published yet",
        "groundedness": "no model published yet",
        "gibberish": "model trained, not yet wired in",
        "toxicity": "model trained, not yet wired in",
        "nsfw": "model trained, not yet wired in",
        "bias": "model trained, not yet wired in",
        "politeness": "model trained, not yet wired in",
        "topic_scope": "needs an encoder export before it can meet its budget",
        "moderation": "trained, but on a seed corpus rather than a training set",
    }
)

#: One line per detector, for a reader who is not going to open the source. Written by
#: hand because a sentence is not derivable from code, and checked for completeness by
#: a test because a blank row in a public table is worse than no table.
SUMMARIES: Final[MappingProxyType[str, str]] = MappingProxyType(
    {
        "secrets": (
            "Credentials in text on its way to the model: named key formats, plus a "
            "deliberately conservative entropy rule."
        ),
        "disclosure": (
            "Reports whether an AI disclosure is present in the output, in 26 "
            "languages, and records the affirmative as well as the absence."
        ),
        "invisible_text": (
            "Characters that are in the text but not on the screen: bidirectional "
            "controls, tag characters used to smuggle instructions, zero-width "
            "characters used to evade filters."
        ),
        "pii": (
            "Personal data in input or output, as named entity spans with checksum "
            "validation where the identifier has one."
        ),
        "output_leakage": (
            "Personal data in the output that the user did not supply, which is the "
            "narrower and more useful question than whether any is present."
        ),
        "banned_terms": (
            "Terms the deploying organisation has decided must not appear, matched "
            "correctly in 26 languages. The list is policy; none ships."
        ),
        "system_prompt_leakage": (
            "Whether the answer gave away the instructions the model was operating "
            "under, by containment against the system prompt and by phrase match in "
            "26 languages."
        ),
        "markup_injection": (
            "Markup in the text that a browser would execute rather than display, "
            "found through case folding, entity decoding and compatibility folding."
        ),
        "internal_domains": (
            "Internal hostnames appearing in an answer meant for someone outside, in "
            "both their Unicode and punycode spellings."
        ),
        "output_format": (
            "Shape assertions a policy states: JSON, HTML, URL presence, length in "
            "graphemes, word count, case, choices, ranges, a regex, reading time."
        ),
        "postal_code": (
            "Postal codes that cannot exist in the countries the product serves: the "
            "wrong shape, or outside a published province or department range."
        ),
        "repetition": (
            "Sentences the answer says twice, compared over folded text so a change of "
            "case or diacritic spelling does not hide a repeat."
        ),
        "json_schema": (
            "Output that does not satisfy a JSON Schema the policy carries. Point it "
            "at the OpenAPI meta-schema and it validates an OpenAPI document."
        ),
        "sql_injection": (
            "Generated SQL that does more than the product asked for: a second "
            "statement, a forbidden statement kind, a tautology, an unexpected UNION."
        ),
        "url_reachability": (
            "Whether links in the answer resolve to something that answers, with a "
            "deadline and a refusal to request private addresses."
        ),
        "gibberish": "Input that is not meaningful text.",
        "injection": "Attempts to talk the model out of its instructions.",
        "moderation": (
            "Thirteen hazard categories in one pass, from violent crime to election "
            "misinformation. Replaces the capability Llama Guard and ShieldGemma "
            "provide, with weights this project can ship."
        ),
        "regulated_advice": (
            "Output that reads as regulated financial, legal or medical advice."
        ),
        "toxicity": "Abusive or hateful language, in input or output.",
        "nsfw": "Sexual or otherwise not-safe-for-work content.",
        "bias": "Output carrying bias related to a protected characteristic.",
        "politeness": "Whether the tone of an answer is acceptable.",
        "topic_scope": (
            "Whether a request is inside the subject matter the product covers."
        ),
        "groundedness": (
            "Whether the claims in an answer are supported by the sources it was given."
        ),
    }
)


class Row(NamedTuple):
    """One detector, as an outside reader needs it."""

    detector_id: str
    tier: str
    sides: str
    status: str
    needs: str
    budget_ms: float
    summary: str


def _loaded() -> frozenset[str]:
    """Which detectors this install provides.

    Imported inside the function because `registry` imports `policy`, which imports
    this package, and a module-level import would be a cycle.
    """
    from flowx_border.registry import loaded_detectors

    return frozenset(loaded_detectors())


def rows() -> tuple[Row, ...]:
    """Every catalogued detector, in tier then name order."""
    loaded = _loaded()
    order = {"T0": 0, "T1": 1, "T2": 2, "T3": 3}
    out = []
    for detector_id in sorted(CATALOGUE, key=lambda d: (order[CATALOGUE[d].tier], d)):
        spec = CATALOGUE[detector_id]
        if detector_id in loaded:
            status = "built"
        else:
            status = NOT_BUILT.get(detector_id, "not built")
        needs = (
            "nothing beyond a CPU"
            if detector_id in CORE
            else ", ".join(sorted(spec.requires))
        )
        out.append(
            Row(
                detector_id=detector_id,
                tier=spec.tier,
                sides=", ".join(sorted(spec.sides)),
                status=status,
                needs=needs,
                budget_ms=spec.budget_ms,
                summary=SUMMARIES[detector_id],
            )
        )
    return tuple(out)


def counts() -> dict[str, int]:
    """The numbers a page is most likely to get wrong, computed rather than recalled."""
    all_rows = rows()
    return {
        "catalogued": len(all_rows),
        "built": sum(1 for row in all_rows if row.status == "built"),
        "not_built": sum(1 for row in all_rows if row.status != "built"),
        "core": len(CORE),
        "outside_core": len(CATALOGUE) - len(CORE),
        "languages": 26,
    }


def render_table() -> str:
    """The detector table."""
    lines = [
        "| detector | tier | side | status | needs | budget | what it does |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in rows():
        budget = f"{row.budget_ms:g} ms"
        lines.append(
            f"| `{row.detector_id}` | {row.tier} | {row.sides} | {row.status} | "
            f"{row.needs} | {budget} | {row.summary} |"
        )
    return "\n".join(lines)


def render_counts() -> str:
    """The summary line, as a table so a renderer can lift it whole."""
    numbers = counts()
    lines = ["| figure | value |", "|---|---|"]
    for key, label in (
        ("catalogued", "detectors in the catalogue"),
        ("built", "implemented and running today"),
        ("not_built", "catalogued but not yet implemented"),
        ("core", "that need nothing beyond a CPU and the base install"),
        ("outside_core", "that need something more, and declare it"),
        ("languages", "supported languages"),
    ):
        lines.append(f"| {label} | {numbers[key]} |")
    return "\n".join(lines)


def render_requirements() -> str:
    """What the non-core detectors ask of a deployment."""
    lines = ["| requirement | meaning |", "|---|---|"]
    for code in sorted(REQUIREMENTS):
        lines.append(f"| `{code}` | {REQUIREMENTS[code]} |")
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover - a convenience for regenerating docs
    print(render_counts())
    print()
    print(render_table())
    print()
    print(render_requirements())
