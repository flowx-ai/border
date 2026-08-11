# SPDX-License-Identifier: Apache-2.0
"""Every Guardrails Hub validator, and what happened to it.

Data, not implementations, like catalogue.py next to it. This is the provenance record
for the port: which of the 65 validators in guardrails-ai/guardrails-hub-monorepo became
a detector here, which did not, and the reason in each case.

**Every one of the 65 is named.** That is the point of the file. An inventory that
listed only the ports would let a reader assume the rest were overlooked, and the
honest answer for most of them is that they were read and rejected. This is the same
shape as `UNSUPPORTED` in adapters/llm_guard_compat.py and for the same reason:
docs/porting-guardrails-validators.md renders its tables from here, so the document and
the decision cannot drift apart.

Licences, checked 2026-08-11 against each validator's pyproject.toml: 64 of the 65
declare MIT and `restricttotopic` declares Apache-2.0. Nothing in the set is a licence
obstacle to this Apache-2.0 project, and no upstream code is copied verbatim in any
case. The licence risk was always in model weights rather than validator code, and it
is recorded per validator below.

`gap` is the field to read next
-------------------------------

A decline is not one thing. `gap=True` means the check is worth having and this library
does not have it, so it is a candidate for a future detector. `gap=False` means it was
considered and is not wanted here, either because a detector already covers it or
because it is not a security or governance check at all. Sorting on that field is what
turns this table into a work list rather than an apology.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Final, NamedTuple


class Port(NamedTuple):
    """A hub validator that became, or fed into, a detector here."""

    detector: str
    note: str


class Decline(NamedTuple):
    """A hub validator that did not become a detector, and why."""

    reason: str
    note: str
    #: True when the check is worth having and is genuinely missing, as opposed to
    #: covered elsewhere or out of scope. Feeds the follow-up review of what a
    #: complete detector set would contain.
    gap: bool = False


#: Reason codes, expanded once here so the per-validator notes stay short and so the
#: rendered document can group by them.
REASONS: Final[MappingProxyType[str, str]] = MappingProxyType(
    {
        "covered": "an existing detector already answers this question",
        "llm": (
            "needs a generative model to make the judgement, which constraint 4 rules "
            "out inside a detector"
        ),
        "network": (
            "needs a network call while scanning, which constraint 1 rules out"
        ),
        "retrain": (
            "kept as a capability, dropped as a port: the upstream weights are "
            "unusable here and the intent is to train our own"
        ),
        "scope": (
            "an output-shape or readability check rather than a security or "
            "governance one"
        ),
        "dependency": (
            "would need a runtime dependency outside the set constraint 7 allows"
        ),
    }
)


#: Hub validator to the detector it became. Six of the seven collapse into one
#: detector, because six packages that each match a different baked-in list are one
#: mechanism with the list taken out.
PORTED: Final[MappingProxyType[str, Port]] = MappingProxyType(
    {
        "ban_list": Port(
            "banned_terms",
            "the base case. Its fuzzy spaceless matching is not carried over, see the "
            "module docstring for the four bugs that come with it.",
        ),
        "contains_string": Port(
            "banned_terms",
            "the same mechanism without word boundaries, which is the "
            "`whole_words: false` option.",
        ),
        "competitor_check": Port(
            "banned_terms",
            "the list half only. Its spaCy named-entity pass does not come along: that "
            "is an English NER model, and this project's entity extraction is "
            "piiguard.",
        ),
        "mentions_drugs": Port(
            "banned_terms",
            "mechanism only. Its English drug list is not shipped, because a drug list "
            "in 26 languages that nobody here can review is worse than no list.",
        ),
        "sky_validator": Port(
            "banned_terms",
            "the term half only. It is one customer's brand check, and the sentiment "
            "half of it is not a term list.",
        ),
        "detect_system_prompt_leakage": Port(
            "system_prompt_leakage",
            "rewritten from whole-string similarity to containment. The original "
            "passes a long answer that quotes the prompt verbatim.",
        ),
        "web_sanitization": Port(
            "markup_injection",
            "rewritten from `bleach.clean(x) != x`, which reports an attack in any "
            "text containing a bare `<`, `>` or `&`.",
        ),
        "internal_domains": Port(
            "internal_domains",
            "kept, with host boundaries on both sides and internationalised domain "
            "spellings added.",
        ),
    }
)


#: Everything else, with the reason. Sorted by hub name when rendered.
DECLINED: Final[MappingProxyType[str, Decline]] = MappingProxyType(
    {
        "bert_toxic": Decline("covered", "`toxicity`."),
        "bias_check": Decline("covered", "`bias`."),
        "cucumber_expression_match": Decline(
            "scope", "matches an output against an expression grammar."
        ),
        "detect_jailbreak": Decline("covered", "`injection`."),
        "detect_pii": Decline("covered", "`pii`. Presidio is not the engine here."),
        "detect_prompt_injection": Decline(
            "llm",
            "calls OpenAI through the Rebuff library. Also covered by `injection`.",
        ),
        "endpoint_is_reachable": Decline("network", "makes an HTTP request to check."),
        "ends_with": Decline("scope", "a suffix assertion about output shape."),
        "exclude_sql_predicates": Decline(
            "dependency",
            "needs a SQL parser, `sqlglot`. A regex over SQL predicates would be worse "
            "than nothing in a check whose whole value is precision.",
            gap=True,
        ),
        "extracted_summary_sentences_match": Decline("llm", "calls OpenAI."),
        "gibberish_text": Decline("covered", "`gibberish`."),
        "guardrails_pii": Decline("covered", "`pii`."),
        "has_url": Decline("scope", "asserts a URL is present."),
        "llamaguard_7b": Decline(
            "retrain",
            "Llama Guard is a 7B generative model under the Llama Community Licence, "
            "which is not Apache-2.0 compatible, and 7B cannot meet a CPU budget. The "
            "capability is wanted: the plan is our own smaller model rather than a "
            "port. See the note in the document about what still has to be decided.",
            gap=True,
        ),
        "llm_critic": Decline("llm", "grades the output with a second model."),
        "logic_check": Decline("llm", "asks a model to find logical fallacies."),
        "lowercase": Decline("scope", "asserts the output is lowercase."),
        "nsfw_text": Decline("covered", "`nsfw`."),
        "one_line": Decline("scope", "asserts the output is a single line."),
        "politeness_check": Decline(
            "llm", "calls a model through litellm. Covered by `politeness`."
        ),
        "presidio_gliner_pii": Decline("covered", "`pii`."),
        "profanity_free": Decline(
            "covered",
            "`toxicity` for the model-backed answer, `banned_terms` for a list you "
            "supply. Its own backend, `alt-profanity-check`, is an English model, so "
            "porting it would add a 26-language claim it cannot support.",
        ),
        "prompt_injection_detector": Decline(
            "llm", "scores prompts with a second model. Covered by `injection`."
        ),
        "provenance_embeddings": Decline("covered", "`groundedness`."),
        "provenance_llm": Decline("llm", "calls a model through litellm."),
        "provenance_nli": Decline("covered", "`groundedness`."),
        "qa_relevance_llm_eval": Decline("llm", "asks the model about its own answer."),
        "quotes_price": Decline("scope", "asserts a price appears."),
        "reading_level": Decline(
            "scope",
            "a US grade-level readability metric. Not a security check, and the "
            "formula is defined for English only, so a 26-language version of it does "
            "not exist to port.",
        ),
        "reading_time": Decline(
            "scope", "estimates how long the output takes to read."
        ),
        "redundant_sentences": Decline("scope", "a writing-quality check."),
        "regex_match": Decline(
            "scope",
            "a regex list belongs in your own code rather than behind a policy schema. "
            "This matches what llm_guard_compat says about the `Regex` scanner.",
        ),
        "relevancy_evaluator": Decline("llm", "calls a model."),
        "response_evaluator": Decline("llm", "calls a model through litellm."),
        "responsiveness_check": Decline("llm", "calls a model through litellm."),
        "restricttotopic": Decline("covered", "`topic_scope`."),
        "saliency_check": Decline("llm", "calls a model through litellm."),
        "secrets_present": Decline(
            "covered",
            "`secrets`, which additionally carries credential keywords in all 26 "
            "languages so its entropy rule fires outside English.",
        ),
        "sensitive_topics": Decline("covered", "`topic_scope`."),
        "shieldgemma_2b": Decline(
            "retrain",
            "ShieldGemma is 2B under the Gemma Terms of Use, which is not Apache-2.0. "
            "Same disposition as llamaguard_7b: the capability is wanted, the weights "
            "are not usable here.",
            gap=True,
        ),
        "similar_to_document": Decline("covered", "`groundedness`."),
        "similar_to_previous_values": Decline(
            "scope", "consistency against previous answers, not a security property."
        ),
        "toxic_language": Decline("covered", "`toxicity`."),
        "toxic_language_llm": Decline("llm", "calls a model through litellm."),
        "two_words": Decline("scope", "asserts the output is exactly two words."),
        "unusual_prompt": Decline(
            "llm", "calls a model through litellm. Covered by `injection`."
        ),
        "uppercase": Decline("scope", "asserts the output is uppercase."),
        "valid_address": Decline(
            "network", "calls the Google Maps Address Validation API."
        ),
        "valid_choices": Decline("scope", "asserts membership of an enumeration."),
        "valid_html": Decline(
            "scope", "parseability, not safety. See `markup_injection`."
        ),
        "valid_json": Decline("scope", "your own schema does this better."),
        "valid_length": Decline("scope", "a length assertion."),
        "valid_open_api_spec": Decline("scope", "validates an OpenAPI document."),
        "valid_range": Decline("scope", "a numeric range assertion."),
        "valid_sql": Decline(
            "dependency",
            "needs `sqlvalidator`, and it is a syntax check rather than a safety one.",
        ),
        "valid_url": Decline("scope", "syntactic URL validation."),
        "wiki_provenance": Decline(
            "llm", "calls a model and fetches Wikipedia while scanning."
        ),
    }
)


def all_validators() -> tuple[str, ...]:
    """Every hub validator name, ported and declined alike, in one sorted tuple."""
    return tuple(sorted(set(PORTED) | set(DECLINED)))


def gaps() -> tuple[str, ...]:
    """Declined validators whose check is worth having and is currently absent.

    The starting point for deciding what a complete detector set looks like, which is
    a separate exercise from this port and is queued rather than done here.
    """
    return tuple(sorted(name for name, entry in DECLINED.items() if entry.gap))


def _row(cells: tuple[str, ...]) -> str:
    return "| " + " | ".join(cells) + " |"


def render_ported_table() -> str:
    """The ported table, grouped by the detector each validator fed into."""
    lines = [
        _row(("hub validator", "detector", "what changed")),
        _row(("---", "---", "---")),
    ]
    for name in sorted(PORTED, key=lambda n: (PORTED[n].detector, n)):
        entry = PORTED[name]
        lines.append(_row((f"`{name}`", f"`{entry.detector}`", entry.note)))
    return "\n".join(lines)


def render_declined_table() -> str:
    """The declined table, grouped by reason then name."""
    lines = [
        _row(("hub validator", "reason", "detail", "gap")),
        _row(("---", "---", "---", "---")),
    ]
    for name in sorted(DECLINED, key=lambda n: (DECLINED[n].reason, n)):
        entry = DECLINED[name]
        lines.append(
            _row(
                (
                    f"`{name}`",
                    entry.reason,
                    entry.note,
                    "yes" if entry.gap else "no",
                )
            )
        )
    return "\n".join(lines)


def render_reasons_table() -> str:
    """What each reason code means."""
    lines = [_row(("reason", "meaning")), _row(("---", "---"))]
    for code in sorted(REASONS):
        lines.append(_row((f"`{code}`", REASONS[code])))
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover - a convenience for regenerating docs
    print(render_reasons_table())
    print()
    print(render_ported_table())
    print()
    print(render_declined_table())
