# Detectors: what exists, what does not

**This file is generated from `src/flowx_border/detectors/reference.py`, which reads the
catalogue and the registry at render time. `tests/test_reference.py` fails if this file
and the code disagree.** If you are describing this library anywhere public, describe it
from here. Regenerate with:

    uv run python -m flowx_border.detectors.reference

## The numbers

| figure | value |
|---|---|
| detectors in the catalogue | 25 |
| implemented and running today | 15 |
| catalogued but not yet implemented | 10 |
| that need nothing beyond a CPU and the base install | 22 |
| that need something more, and declare it | 3 |
| supported languages | 26 |

`status` is derived from whether the detector is in the registry, not from a list
somebody keeps up to date. A detector that stops loading changes this table on the next
render.

`needs` is what a deployment must provide before the detector will run at all. Most need
nothing. The ones that do declare it in the catalogue, and
`registry.deployment_notes(policy)` returns a line naming them when a policy switches
one on, so a caller finds out when they enable it rather than in production.

## The detectors

| detector | tier | side | status | needs | budget | what it does |
|---|---|---|---|---|---|---|
| `disclosure` | T0 | output | built | nothing beyond a CPU | 5 ms | Reports whether an AI disclosure is present in the output, in 26 languages, and records the affirmative as well as the absence. |
| `invisible_text` | T0 | input, output | built | nothing beyond a CPU | 5 ms | Characters that are in the text but not on the screen: bidirectional controls, tag characters used to smuggle instructions, zero-width characters used to evade filters. |
| `secrets` | T0 | input | built | nothing beyond a CPU | 1 ms | Credentials in text on its way to the model: named key formats, plus a deliberately conservative entropy rule. |
| `banned_terms` | T1 | input, output | built | nothing beyond a CPU | 5 ms | Terms the deploying organisation has decided must not appear, matched correctly in 26 languages. The list is policy; none ships. |
| `gibberish` | T1 | input | model trained, not yet wired in | nothing beyond a CPU | 75 ms | Input that is not meaningful text. |
| `internal_domains` | T1 | output | built | nothing beyond a CPU | 5 ms | Internal hostnames appearing in an answer meant for someone outside, in both their Unicode and punycode spellings. |
| `json_schema` | T1 | output | built | dependency | 5 ms | Output that does not satisfy a JSON Schema the policy carries. Point it at the OpenAPI meta-schema and it validates an OpenAPI document. |
| `markup_injection` | T1 | input, output | built | nothing beyond a CPU | 5 ms | Markup in the text that a browser would execute rather than display, found through case folding, entity decoding and compatibility folding. |
| `output_format` | T1 | output | built | nothing beyond a CPU | 5 ms | Shape assertions a policy states: JSON, HTML, URL presence, length in graphemes, word count, case, choices, ranges, a regex, reading time. |
| `output_leakage` | T1 | output | built | nothing beyond a CPU | 75 ms | Personal data in the output that the user did not supply, which is the narrower and more useful question than whether any is present. |
| `pii` | T1 | input, output | built | nothing beyond a CPU | 75 ms | Personal data in input or output, as named entity spans with checksum validation where the identifier has one. |
| `postal_code` | T1 | output | built | nothing beyond a CPU | 5 ms | Postal codes that cannot exist in the countries the product serves: the wrong shape, or outside a published province or department range. |
| `repetition` | T1 | output | built | nothing beyond a CPU | 5 ms | Sentences the answer says twice, compared over folded text so a change of case or diacritic spelling does not hide a repeat. |
| `sql_injection` | T1 | output | built | dependency | 5 ms | Generated SQL that does more than the product asked for: a second statement, a forbidden statement kind, a tautology, an unexpected UNION. |
| `system_prompt_leakage` | T1 | output | built | nothing beyond a CPU | 5 ms | Whether the answer gave away the instructions the model was operating under, by containment against the system prompt and by phrase match in 26 languages. |
| `bias` | T2 | output | model trained, not yet wired in | nothing beyond a CPU | 75 ms | Output carrying bias related to a protected characteristic. |
| `injection` | T2 | input | no model published yet | nothing beyond a CPU | 75 ms | Attempts to talk the model out of its instructions. |
| `moderation` | T2 | input, output | trained, but on a seed corpus rather than a training set | nothing beyond a CPU | 150 ms | Thirteen hazard categories in one pass, from violent crime to election misinformation. Replaces the capability Llama Guard and ShieldGemma provide, with weights this project can ship. |
| `nsfw` | T2 | input, output | model trained, not yet wired in | nothing beyond a CPU | 75 ms | Sexual or otherwise not-safe-for-work content. |
| `politeness` | T2 | output | model trained, not yet wired in | nothing beyond a CPU | 75 ms | Whether the tone of an answer is acceptable. |
| `regulated_advice` | T2 | output | no model published yet | nothing beyond a CPU | 75 ms | Output that reads as regulated financial, legal or medical advice. |
| `toxicity` | T2 | input, output | model trained, not yet wired in | nothing beyond a CPU | 75 ms | Abusive or hateful language, in input or output. |
| `groundedness` | T3 | output | no model published yet | nothing beyond a CPU | 300 ms | Whether the claims in an answer are supported by the sources it was given. |
| `topic_scope` | T3 | input | needs an encoder export before it can meet its budget | nothing beyond a CPU | 300 ms | Whether a request is inside the subject matter the product covers. |
| `url_reachability` | T3 | output | built | network | 3000 ms | Whether links in the answer resolve to something that answers, with a deadline and a refusal to request private addresses. |

## What the non-core detectors ask for

| requirement | meaning |
|---|---|
| `dependency` | needs a runtime dependency outside the base install |
| `gpu` | needs an accelerator to meet its budget; CPU will be far slower |
| `llm` | runs a generative model, so its verdict is only reproducible with decoding pinned, and an evidence record depends on that |
| `network` | reaches another machine during a scan, so a third party is in the latency path of every request and their outage becomes yours |

## Things that are true and are easy to get wrong

Written as a list because these are the claims most likely to end up on a page in a
form that is not quite right.

**Not every catalogued detector is implemented.** The table above is the authority. A
detector with a status other than `built` does not run, and the library says so loudly
rather than passing silently: a policy that asks an unavailable detector to block or
redact raises `DetectorUnavailableError` before any scan happens, rather than letting
text through as if it were checked.

**26 languages is a claim about the rule-based detectors and about fixtures, not about
every model.** Every detector has fixtures in all 26. The PII model, `piiguard`, was
trained on nine of them: English, Romanian, Bulgarian, Hungarian, Slovenian, Croatian,
German, Italian and French. The other seventeen are untested for that detector. Say
nine, or say "fixtures in 26, model coverage in 9", but do not say the model covers 26.

**Two languages are weaker than the rest by construction.** Maltese is not in the base
model's pretraining set, and Maltese and Azerbaijani national identifiers have no public
checksum scheme, so identifiers in those two can only be generated format-valid.

**The disclosure and system-prompt phrasing files are not reviewed by native speakers.**
All 26 entries in both are marked `reviewed: false`. They match obvious wording and will
miss idiomatic wording. `unreviewed_languages()` returns the list.

**One detector answers no security question.** `output_format` is shape, and its own
docstring says so. It exists so that sixteen upstream shape validators have one
destination instead of sixteen.

**Latency figures need their input attached.** Every budget above is p95 at a named
reference input: 87 tokens, 396 characters, one thread, CPU, INT8 weights. The exact
string is `REFERENCE_INPUT` in `tests/test_budgets.py`. A millisecond figure quoted
without that is not reproducible. `url_reachability` is the exception and its budget is
a deadline it enforces on itself, because it depends on a network.

**A scan runs on one thread by default.** More threads are faster, and the default stays
at one because a library that commandeers the machine it is embedded in is worse than
one that is honestly slower. A policy can raise it.

## Things that must not be said

These are not style preferences. The obligations under the EU AI Act sit with the
provider or deployer of a system, not with a library, and a claim otherwise is
materially misleading.

Do not write: "AI Act compliant", "makes your system compliant", "guarantees",
"ensures", "certified", or the name of any specific regulation in a way that implies
this library satisfies it.

Write instead: "produces an auditable record of which checks ran and what they found",
"detects whether a required disclosure is present in the output", "supports the evidence
requirements of your own AI governance process".

The distinction the whole project rests on: this library does not make anyone compliant
with anything. It produces evidence about controls that were applied.
