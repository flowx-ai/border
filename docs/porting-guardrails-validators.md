# Porting the Guardrails Hub validators

[guardrails-ai/guardrails-hub-monorepo](https://github.com/guardrails-ai/guardrails-hub-monorepo)
ships 65 validators. This is what happened to each of them, and why. The tables are
rendered from `PORTED`, `DECLINED` and `REASONS` in
`src/flowx_border/detectors/guardrails_hub.py`, so the document cannot drift away from
the decision. `tests/test_guardrails_hub.py` fails if it does.

Eight validators became four detectors. Fifty-seven were declined. Every one of the 65
is named below, because an inventory that listed only the ports would let a reader
assume the rest were overlooked, and for most of them the honest answer is that they
were read and rejected.

## What the port was for

The brief was "improved for all languages". That is the whole justification: an
English-only port of an English-only validator is not worth the maintenance, because it
is what the original already is. So the improvement had to be something a 26-language
deployment can measure, and in every case it turned out to be the same thing. These
validators match text against strings, and each does it in a way that is correct in
English and wrong somewhere in Europe.

`src/flowx_border/detectors/multilingual.py` is where that is fixed once for all four,
and `tests/test_multilingual.py` reproduces each upstream behaviour as the thing that
must not happen again. The four that mattered:

- **`str.lower()` is not `str.casefold()`.** German `Straße` and `STRASSE` are one word
  and `lower` leaves them as two. Greek is narrower than it first looks: Python's
  `lower` does implement the final-sigma rule, so it gets `ΛΑΘΟΣ` right, but it does not
  unify ς with σ, so the medial spelling any non-Greek keyboard produces stays a
  different string. `ban_list` uses `lower`.
- **Romanian ș is two characters.** U+0219 with a comma below and U+015F with a cedilla
  are both in daily use for one letter, because a generation of software emitted the
  Turkish form. NFC does not unify them. Unmerged, a Romanian term list matches roughly
  half of Romanian text.
- **Turkish İ casefolds to two characters**, `i` plus a combining dot above, so
  casefolding alone does not make `İSTANBUL` match `istanbul`.
- **Zero-width characters are an evasion, not a typo.** No upstream validator here drops
  them, so `ac<U+200B>me` defeats every one of them.

Two things follow that are worth stating plainly. Spans are reported into the caller's
original string, not into the folded one, because the engine redacts spans without
checking them and a span that is off by one redacts the wrong characters. And no port
carries over fuzzy matching: edit distance one absorbs typos in English and merges real
unrelated words in Romanian, Polish and Finnish.

## What each detector costs

All four are rules. They sit at T1 with a 5 ms budget rather than the 75 ms an
encoder-backed detector carries, and they need no weights, so they work on a machine
that has never downloaded a model. `tests/test_budgets.py` asserts the budgets at the
reference input named there.

## Reason codes

| reason | meaning |
| --- | --- |
| `covered` | an existing detector already answers this question |
| `dependency` | would need a runtime dependency outside the set constraint 7 allows |
| `llm` | needs a generative model to make the judgement, which constraint 4 rules out inside a detector |
| `network` | needs a network call while scanning, which constraint 1 rules out |
| `retrain` | kept as a capability, dropped as a port: the upstream weights are unusable here and the intent is to train our own |
| `scope` | an output-shape or readability check rather than a security or governance one |

## Ported

Six of the eight collapse into one detector. `ban_list`, `contains_string`,
`competitor_check`, `mentions_drugs` and `sky_validator` are the same mechanism with a
different list baked in, and the list in every case is the deployer's data rather than
the library's, so the port ships the mechanism and asks for the list.

**No wordlist ships with this library, in any language.** A competitor list, a drug list
and a profanity list are customer-specific, they change without a release, and a library
that shipped its own would be asserting an editorial judgement it cannot defend in 26
languages. `banned_terms` and `internal_domains` are therefore disabled in
`policies/default.yaml`, and when they are enabled without a list they report
`terms_not_configured` and `domains_not_configured` at action `log` rather than
reporting a clean scan.

| hub validator | detector | what changed |
| --- | --- | --- |
| `ban_list` | `banned_terms` | the base case. Its fuzzy spaceless matching is not carried over, see the module docstring for the four bugs that come with it. |
| `competitor_check` | `banned_terms` | the list half only. Its spaCy named-entity pass does not come along: that is an English NER model, and this project's entity extraction is piiguard. |
| `contains_string` | `banned_terms` | the same mechanism without word boundaries, which is the `whole_words: false` option. |
| `mentions_drugs` | `banned_terms` | mechanism only. Its English drug list is not shipped, because a drug list in 26 languages that nobody here can review is worse than no list. |
| `sky_validator` | `banned_terms` | the term half only. It is one customer's brand check, and the sentiment half of it is not a term list. |
| `internal_domains` | `internal_domains` | kept, with host boundaries on both sides and internationalised domain spellings added. |
| `web_sanitization` | `markup_injection` | rewritten from `bleach.clean(x) != x`, which reports an attack in any text containing a bare `<`, `>` or `&`. |
| `detect_system_prompt_leakage` | `system_prompt_leakage` | rewritten from whole-string similarity to containment. The original passes a long answer that quotes the prompt verbatim. |

## Declined

`gap` is the column to read. `yes` means the check is worth having and this library does
not have it, so it is a candidate for a future detector. `no` means it was considered and
is not wanted here, either because a detector already covers it or because it is not a
security or governance check at all.

| hub validator | reason | detail | gap |
| --- | --- | --- | --- |
| `bert_toxic` | covered | `toxicity`. | no |
| `bias_check` | covered | `bias`. | no |
| `detect_jailbreak` | covered | `injection`. | no |
| `detect_pii` | covered | `pii`. Presidio is not the engine here. | no |
| `gibberish_text` | covered | `gibberish`. | no |
| `guardrails_pii` | covered | `pii`. | no |
| `nsfw_text` | covered | `nsfw`. | no |
| `presidio_gliner_pii` | covered | `pii`. | no |
| `profanity_free` | covered | `toxicity` for the model-backed answer, `banned_terms` for a list you supply. Its own backend, `alt-profanity-check`, is an English model, so porting it would add a 26-language claim it cannot support. | no |
| `provenance_embeddings` | covered | `groundedness`. | no |
| `provenance_nli` | covered | `groundedness`. | no |
| `restricttotopic` | covered | `topic_scope`. | no |
| `secrets_present` | covered | `secrets`, which additionally carries credential keywords in all 26 languages so its entropy rule fires outside English. | no |
| `sensitive_topics` | covered | `topic_scope`. | no |
| `similar_to_document` | covered | `groundedness`. | no |
| `toxic_language` | covered | `toxicity`. | no |
| `exclude_sql_predicates` | dependency | needs a SQL parser, `sqlglot`. A regex over SQL predicates would be worse than nothing in a check whose whole value is precision. | yes |
| `valid_sql` | dependency | needs `sqlvalidator`, and it is a syntax check rather than a safety one. | no |
| `detect_prompt_injection` | llm | calls OpenAI through the Rebuff library. Also covered by `injection`. | no |
| `extracted_summary_sentences_match` | llm | calls OpenAI. | no |
| `llm_critic` | llm | grades the output with a second model. | no |
| `logic_check` | llm | asks a model to find logical fallacies. | no |
| `politeness_check` | llm | calls a model through litellm. Covered by `politeness`. | no |
| `prompt_injection_detector` | llm | scores prompts with a second model. Covered by `injection`. | no |
| `provenance_llm` | llm | calls a model through litellm. | no |
| `qa_relevance_llm_eval` | llm | asks the model about its own answer. | no |
| `relevancy_evaluator` | llm | calls a model. | no |
| `response_evaluator` | llm | calls a model through litellm. | no |
| `responsiveness_check` | llm | calls a model through litellm. | no |
| `saliency_check` | llm | calls a model through litellm. | no |
| `toxic_language_llm` | llm | calls a model through litellm. | no |
| `unusual_prompt` | llm | calls a model through litellm. Covered by `injection`. | no |
| `wiki_provenance` | llm | calls a model and fetches Wikipedia while scanning. | no |
| `endpoint_is_reachable` | network | makes an HTTP request to check. | no |
| `valid_address` | network | calls the Google Maps Address Validation API. | no |
| `llamaguard_7b` | retrain | Llama Guard is a 7B generative model under the Llama Community Licence, which is not Apache-2.0 compatible, and 7B cannot meet a CPU budget. The capability is wanted: the plan is our own smaller model rather than a port. See the note in the document about what still has to be decided. | yes |
| `shieldgemma_2b` | retrain | ShieldGemma is 2B under the Gemma Terms of Use, which is not Apache-2.0. Same disposition as llamaguard_7b: the capability is wanted, the weights are not usable here. | yes |
| `cucumber_expression_match` | scope | matches an output against an expression grammar. | no |
| `ends_with` | scope | a suffix assertion about output shape. | no |
| `has_url` | scope | asserts a URL is present. | no |
| `lowercase` | scope | asserts the output is lowercase. | no |
| `one_line` | scope | asserts the output is a single line. | no |
| `quotes_price` | scope | asserts a price appears. | no |
| `reading_level` | scope | a US grade-level readability metric. Not a security check, and the formula is defined for English only, so a 26-language version of it does not exist to port. | no |
| `reading_time` | scope | estimates how long the output takes to read. | no |
| `redundant_sentences` | scope | a writing-quality check. | no |
| `regex_match` | scope | a regex list belongs in your own code rather than behind a policy schema. This matches what llm_guard_compat says about the `Regex` scanner. | no |
| `similar_to_previous_values` | scope | consistency against previous answers, not a security property. | no |
| `two_words` | scope | asserts the output is exactly two words. | no |
| `uppercase` | scope | asserts the output is uppercase. | no |
| `valid_choices` | scope | asserts membership of an enumeration. | no |
| `valid_html` | scope | parseability, not safety. See `markup_injection`. | no |
| `valid_json` | scope | your own schema does this better. | no |
| `valid_length` | scope | a length assertion. | no |
| `valid_open_api_spec` | scope | validates an OpenAPI document. | no |
| `valid_range` | scope | a numeric range assertion. | no |
| `valid_url` | scope | syntactic URL validation. | no |

## The two moderation models

`llamaguard_7b` and `shieldgemma_2b` are the only entries whose value is entirely in
model weights this project cannot ship. Llama Guard is 7B under the Llama Community
Licence and ShieldGemma is 2B under the Gemma Terms of Use; neither is Apache-2.0
compatible, and porting the code without the weights would be shipping a shell.

The decision on 2026-08-11 was to keep the capability and drop the port: train our own
on a smaller Qwen base rather than depend on either. Two things still have to be settled
before that is a detector rather than a plan, and they are the same two that
`semantic-mapper` ran into:

- **Constraint 4 forbids an LLM call inside a detector.** A generative model that reads
  a policy and writes a verdict is that, whatever its size. A classification head on the
  same base is not, and would also be far cheaper.
- **A 1.6B model does not meet a CPU budget.** The encoder detectors here are 278M and
  cost 51 ms at the reference input. 1.6B generative is orders of magnitude away from
  the 75 ms tier, and the T3 ceiling is 300 ms.

Both point the same way: a distilled encoder head rather than a generative model. That
is a training decision rather than a library one, so it is recorded here rather than
resolved here.

## Queued: what a complete detector set would contain

This port answered "which hub validators are worth having". It did not answer "what is
missing from the detector set as a whole", which is a separate exercise and is queued
after the migration rather than folded into it.

The raw material is already assembled. Three sources feed it:

- The `gap = yes` rows in the declined table above.
- The `UNSUPPORTED` table in `src/flowx_border/adapters/llm_guard_compat.py`, whose
  `InvisibleText` entry is flagged in `docs/migrating-from-llm-guard.md` as a real gap
  rather than a rejected idea. It is pure rules and would cost nothing, and the folding
  in `multilingual.py` now does most of its work already.
- The three detectors that ship unavailable because no model is published for them:
  `injection`, `regulated_advice`, `groundedness`.

The exercise is to turn those into a proposal with a tier and a budget for each, not to
add them.
