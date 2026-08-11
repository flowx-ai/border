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
            "needs a generative model to make the judgement, and no detector here "
            "answers the same question. Permitted since 2026-08-11, when the "
            "constraints were lifted, and not yet built: there is no published model "
            "for it. Filed by what this library can answer rather than by how upstream "
            "implements it, so nine validators that call an LLM upstream are listed as "
            "covered instead"
        ),
        "network": (
            "needs a network call while scanning. Permitted since 2026-08-11 and not "
            "yet built, and the cost is worth stating: it puts a third party in the "
            "latency path of every scan and breaks the offline guarantee "
            "tests/conftest.py enforces"
        ),
        "dependency": (
            "needs a runtime dependency the project does not have yet. Permitted since "
            "2026-08-11, so this is a decision about weight rather than a refusal"
        ),
        "retrain": (
            "kept as a capability, dropped as a port: the upstream weights are "
            "unusable "
            "here and the intent is to train our own"
        ),
        "scope": (
            "the check itself does not survive the port. Each of the four is a "
            "specific "
            "reason rather than a category judgement, and the note says which"
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
        # The sixteen shape validators, collapsed the same way the term-list ones were.
        # Each hard-codes one assertion upstream; here the assertion is a policy option
        # and the sixteen packages are one detector. See its module docstring for the
        # four places a shape check stops being language-neutral.
        "valid_json": Port("output_format", "`json: true`."),
        "valid_html": Port(
            "output_format",
            "`html: true`, which counts unclosed tags. `html.parser` never fails on "
            "its own, so parsing alone would be a no-op.",
        ),
        "valid_url": Port("output_format", "`url: required`."),
        "has_url": Port("output_format", "`url: required`, the same option."),
        "valid_length": Port(
            "output_format",
            "`max_length` and `min_length`, counted in graphemes rather than code "
            "points so one visible string is one length in every language.",
        ),
        "one_line": Port("output_format", "`one_line: true`."),
        "lowercase": Port(
            "output_format",
            "`case: lower`, asked as `text == text.lower()`. The obvious formulation, "
            "no character is uppercase, passes the Croatian titlecase digraphs.",
        ),
        "uppercase": Port("output_format", "`case: upper`, as above."),
        "valid_choices": Port(
            "output_format",
            "`choices`, matched on folded text so a Romanian choice accepts either "
            "spelling of its diacritic.",
        ),
        "valid_range": Port(
            "output_format",
            "`numeric_range`, accepting a comma decimal separator, which is correct in "
            "most of the 26.",
        ),
        "ends_with": Port("output_format", "`ends_with`, and `starts_with` with it."),
        "regex_match": Port(
            "output_format", "`regex`, as a full match rather than a search."
        ),
        "cucumber_expression_match": Port(
            "output_format",
            "`regex`. The cucumber expression grammar is not carried over: it is a "
            "test-fixture DSL, and the shape it expresses is a regex here.",
        ),
        "two_words": Port("output_format", "`max_words: 2` with `min_words: 2`."),
        "reading_time": Port(
            "output_format",
            "`max_reading_seconds`, with `words_per_minute` as an option rather than a "
            "constant. Upstream bakes in an English silent-reading rate and applies it "
            "to every language.",
        ),
        "quotes_price": Port(
            "output_format", "`regex`. A price assertion is a pattern, not a feature."
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
        "detect_jailbreak": Decline("covered", "`injection`."),
        "detect_pii": Decline("covered", "`pii`. Presidio is not the engine here."),
        "detect_prompt_injection": Decline(
            "covered",
            "`injection`. Upstream calls OpenAI through the Rebuff library to "
            "answer it; the encoder here answers the same question locally.",
        ),
        "endpoint_is_reachable": Decline(
            "network", "makes an HTTP request to check.", gap=True
        ),
        "exclude_sql_predicates": Decline(
            "dependency",
            "needs a SQL parser, `sqlglot`. A regex over SQL predicates would be worse "
            "than nothing in a check whose whole value is precision.",
            gap=True,
        ),
        "extracted_summary_sentences_match": Decline("llm", "calls OpenAI.", gap=True),
        "gibberish_text": Decline("covered", "`gibberish`."),
        "guardrails_pii": Decline("covered", "`pii`."),
        "llamaguard_7b": Decline(
            "retrain",
            "Llama Guard is a 7B generative model under the Llama Community Licence, "
            "which is not Apache-2.0 compatible, and 7B cannot meet a CPU budget. The "
            "capability is wanted: the plan is our own smaller model rather than a "
            "port. See the note in the document about what still has to be decided.",
            gap=True,
        ),
        "llm_critic": Decline(
            "llm", "grades the output with a second model.", gap=True
        ),
        "logic_check": Decline(
            "llm", "asks a model to find logical fallacies.", gap=True
        ),
        "nsfw_text": Decline("covered", "`nsfw`."),
        "politeness_check": Decline(
            "covered", "`politeness`. Upstream calls a model through litellm."
        ),
        "presidio_gliner_pii": Decline("covered", "`pii`."),
        "profanity_free": Decline(
            "covered",
            "`toxicity` for the model-backed answer, `banned_terms` for a list you "
            "supply. Its own backend, `alt-profanity-check`, is an English model, so "
            "porting it would add a 26-language claim it cannot support.",
        ),
        "prompt_injection_detector": Decline(
            "covered", "`injection`. Upstream scores the prompt with a second model."
        ),
        "provenance_embeddings": Decline("covered", "`groundedness`."),
        "provenance_llm": Decline(
            "covered",
            "`groundedness`. Upstream calls a model through litellm to compare an "
            "answer with its sources.",
        ),
        "provenance_nli": Decline("covered", "`groundedness`."),
        "qa_relevance_llm_eval": Decline(
            "covered",
            "`topic_scope`. Upstream asks the model whether its own answer was "
            "relevant, which is a model grading itself.",
        ),
        "reading_level": Decline(
            "scope",
            "a US grade-level readability metric. Not a security check, and the "
            "formula is defined for English only, so a 26-language version of it does "
            "not exist to port.",
        ),
        "redundant_sentences": Decline("scope", "a writing-quality check.", gap=True),
        "relevancy_evaluator": Decline(
            "covered", "`topic_scope`. Upstream calls a model."
        ),
        "response_evaluator": Decline(
            "llm", "calls a model through litellm.", gap=True
        ),
        "responsiveness_check": Decline(
            "covered",
            "`politeness`. Its description is the same as politeness_check's, and "
            "so is its implementation.",
        ),
        "restricttotopic": Decline("covered", "`topic_scope`."),
        "saliency_check": Decline("llm", "calls a model through litellm.", gap=True),
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
            "scope",
            "consistency against previous answers, not a security property.",
            gap=True,
        ),
        "toxic_language": Decline("covered", "`toxicity`."),
        "toxic_language_llm": Decline(
            "covered",
            "`toxicity`. Upstream asks a model for the same seven categories the "
            "classifier here scores.",
        ),
        "unusual_prompt": Decline(
            "covered",
            "`injection`. Upstream asks a model whether the prompt is tricky.",
        ),
        "valid_address": Decline(
            "network",
            "calls the Google Maps Address Validation API.",
            gap=True,
        ),
        "valid_open_api_spec": Decline(
            "scope", "validates an OpenAPI document.", gap=True
        ),
        "valid_sql": Decline(
            "dependency",
            "needs `sqlvalidator`, and it is a syntax check rather than a safety one.",
            gap=True,
        ),
        "wiki_provenance": Decline(
            "llm",
            "calls a model and fetches Wikipedia while scanning.",
            gap=True,
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
