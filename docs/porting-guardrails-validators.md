# Porting the Guardrails Hub validators

[guardrails-ai/guardrails-hub-monorepo](https://github.com/guardrails-ai/guardrails-hub-monorepo)
ships 65 validators. This is what happened to each of them. The tables are rendered from
`PORTED`, `DECLINED` and `REASONS` in `src/flowx_border/detectors/guardrails_hub.py`, so
the document cannot drift away from the decision. `tests/test_guardrails_hub.py` fails
if it does.

**Thirty-one validators became nine detectors. Twenty-five are already answered by a
detector that exists. Nine are not built, and each says what it would need.**

Of those nine, six need a local generative model that does not exist yet, two are
the Llama Guard and ShieldGemma retrains, and one is the vendor half of
`valid_address`. Nothing is left that is declined for want of effort alone.

That last group used to say "declined". It changed on 2026-08-11, when the constraints
that blocked most of them stopped being prohibitions. A validator that needs a network
round trip or a generative model is now a thing to build and tag, not a thing to refuse.
See the packages section of `CLAUDE.md`: what a detector needs is declared in
`Spec.requires`, and `registry.deployment_notes` tells the caller at policy load.

## What the port was for

The brief was "improved for all languages". An English-only port of an English-only
validator is not worth the maintenance, because it is what the original already is. So
the improvement had to be something a 26-language deployment can measure, and in every
case it turned out to be the same thing: these validators match text against strings,
and each does it in a way that is correct in English and wrong somewhere in Europe.

`src/flowx_border/detectors/multilingual.py` fixes that once for all five, and
`tests/test_multilingual.py` reproduces each upstream behaviour as the thing that must
not happen again:

- **`str.lower()` is not `str.casefold()`.** German `Straße` and `STRASSE` are one word
  and `lower` leaves them as two. Greek is narrower than it first looks: Python's `lower`
  does implement the final-sigma rule, so it gets `ΛΑΘΟΣ` right, but it does not unify ς
  with σ, so the medial spelling any non-Greek keyboard produces stays a different
  string. `ban_list` uses `lower`.
- **Romanian ș is two characters.** U+0219 with a comma below and U+015F with a cedilla
  are both in daily use for one letter, because a generation of software emitted the
  Turkish form. NFC does not unify them. Unmerged, a Romanian term list matches roughly
  half of Romanian text.
- **Turkish İ casefolds to two characters**, `i` plus a combining dot above, so
  casefolding alone does not make `İSTANBUL` match `istanbul`.
- **Zero-width characters are an evasion, not a typo.** No upstream validator here drops
  them, so `ac<U+200B>me` defeats every one of them.
- **Length is graphemes, not code points**, and **the Croatian titlecase digraphs are
  neither upper nor lower**. Both are in `output_format`, and both are wrong in the
  obvious implementation.

Spans are reported into the caller's original string, not the folded one, because the
engine redacts spans without checking them and a span off by one redacts the wrong
characters. No port carries over fuzzy matching: edit distance one absorbs typos in
English and merges real unrelated words in Romanian, Polish and Finnish.

## What each detector costs

Six of the seven are rules rather than models, so they sit at T1 with a 5 ms budget
rather than the 75 ms an encoder-backed detector carries, and none of them has weights.
Measured p95 at the reference input: `banned_terms` 0.23, `system_prompt_leakage` 0.36,
`markup_injection` 0.23, `internal_domains` 0.23, `output_format` 0.02 and
`sql_injection` 0.22 ms. `tests/test_budgets.py` asserts them.

Five of the seven are in `CORE` and work on a machine that has never downloaded a model
and has no network. Two are not, and they are the worked examples of the packaging:

- `sql_injection` needs the sqlglot parser, so it declares `requires={"dependency"}`,
  ships in the `sql` extra, and is absent from the registry rather than degraded to a
  pass when that extra is not installed.
- `url_reachability` makes an HTTP request, so it declares `requires={"network"}` and
  is T3 rather than T1. Its budget is the odd one in the whole table: it is a deadline
  the detector enforces on itself rather than a figure somebody measured, because it
  depends on a network the library does not control. The deadline is total across every
  URL in a scan, not per request, since per-request timeouts multiply by the number of
  links and a model can emit fifty.

Either one produces a line from `registry.deployment_notes` when a policy enables it,
and both are disabled in the shipped policies.

## Reason codes

| reason | meaning |
| --- | --- |
| `covered` | an existing detector already answers this question |
| `llm` | needs a generative model to make the judgement, and no detector here answers the same question. Permitted since 2026-08-11, when the constraints were lifted, and not yet built: there is no published model for it. Filed by what this library can answer rather than by how upstream implements it, so nine validators that call an LLM upstream are listed as covered instead |
| `retrain` | kept as a capability, dropped as a port: the upstream weights are unusable here and the intent is to train our own |
| `vendor` | is a wrapper around one commercial service rather than a check. Porting it would mean shipping that vendor relationship, its credential and its terms, inside a library, and the thing being sent is customer data |

## Ported

Thirty-one validators, nine detectors. Two collapses do most of the work.

`ban_list`, `contains_string`, `competitor_check`, `mentions_drugs` and `sky_validator`
are one mechanism with a different list baked in, and the list in every case is the
deployer's data rather than the library's. `valid_json` through `quotes_price` are
sixteen packages that each hard-code one shape assertion, and the assertion is the
deployer's too.

**No wordlist and no shape ships with this library.** `banned_terms`,
`internal_domains` and `output_format` are disabled in `policies/default.yaml`, and
enabled without configuration they report `terms_not_configured`,
`domains_not_configured` and `format_not_configured` at action `log` rather than
reporting a clean scan.

`output_format` is the one detector here that answers no security question, and it says
so in its own docstring. It exists so that sixteen shape validators have one destination
instead of sixteen.

| hub validator | detector | what changed |
| --- | --- | --- |
| `ban_list` | `banned_terms` | the base case. Its fuzzy spaceless matching is not carried over, see the module docstring for the four bugs that come with it. |
| `competitor_check` | `banned_terms` | the list half only. Its spaCy named-entity pass does not come along: that is an English NER model, and this project's entity extraction is piiguard. |
| `contains_string` | `banned_terms` | the same mechanism without word boundaries, which is the `whole_words: false` option. |
| `mentions_drugs` | `banned_terms` | mechanism only. Its English drug list is not shipped, because a drug list in 26 languages that nobody here can review is worse than no list. |
| `sky_validator` | `banned_terms` | the term half only. It is one customer's brand check, and the sentiment half of it is not a term list. |
| `internal_domains` | `internal_domains` | kept, with host boundaries on both sides and internationalised domain spellings added. |
| `valid_open_api_spec` | `json_schema` | generalised. Upstream validates against one schema; this validates against whichever schema the policy carries, and pointing it at the OpenAPI meta-schema is the original. |
| `web_sanitization` | `markup_injection` | rewritten from `bleach.clean(x) != x`, which reports an attack in any text containing a bare `<`, `>` or `&`. |
| `cucumber_expression_match` | `output_format` | `regex`. The cucumber expression grammar is not carried over: it is a test-fixture DSL, and the shape it expresses is a regex here. |
| `ends_with` | `output_format` | `ends_with`, and `starts_with` with it. |
| `has_url` | `output_format` | `url: required`, the same option. |
| `lowercase` | `output_format` | `case: lower`, asked as `text == text.lower()`. The obvious formulation, no character is uppercase, passes the Croatian titlecase digraphs. |
| `one_line` | `output_format` | `one_line: true`. |
| `quotes_price` | `output_format` | `regex`. A price assertion is a pattern, not a feature. |
| `reading_level` | `output_format` | `max_lix`. Its Flesch-Kincaid counts syllables by English rules and does not survive the trip, so LIX is used instead: sentence length plus the share of long words, computable identically in all 26. The scale is not comparable between languages, which is why the threshold has no default. |
| `reading_time` | `output_format` | `max_reading_seconds`, with `words_per_minute` as an option rather than a constant. Upstream bakes in an English silent-reading rate and applies it to every language. |
| `regex_match` | `output_format` | `regex`, as a full match rather than a search. |
| `similar_to_previous_values` | `output_format` | `choices` with `choices_similarity`. Upstream compares with sentence-transformer embeddings; a ratio over the folded strings answers the same question for the case it is used for, and needs no model. |
| `two_words` | `output_format` | `max_words: 2` with `min_words: 2`. |
| `uppercase` | `output_format` | `case: upper`, as above. |
| `valid_choices` | `output_format` | `choices`, matched on folded text so a Romanian choice accepts either spelling of its diacritic. |
| `valid_html` | `output_format` | `html: true`, which counts unclosed tags. `html.parser` never fails on its own, so parsing alone would be a no-op. |
| `valid_json` | `output_format` | `json: true`. |
| `valid_length` | `output_format` | `max_length` and `min_length`, counted in graphemes rather than code points so one visible string is one length in every language. |
| `valid_range` | `output_format` | `numeric_range`, accepting a comma decimal separator, which is correct in most of the 26. |
| `valid_url` | `output_format` | `url: required`. |
| `redundant_sentences` | `repetition` | the two dependencies are gone: stdlib difflib replaces `thefuzz` and multilingual.sentences replaces `nltk`, which is what keeps the detector in CORE. |
| `exclude_sql_predicates` | `sql_injection` | inverted into an allowlist of statement kinds. A denylist of SQL statement types is a list somebody has to keep complete, and the consequence of missing one is a statement that runs. |
| `valid_sql` | `sql_injection` | the parse half. Reported as `sql_unparseable` rather than as its own detector, because whether generated SQL parses and whether it does more than was asked are the same question with one parser behind it. |
| `extracted_summary_sentences_match` | `summary_support` | the hub validator asks an LLM whether each summary sentence appears in the source. difflib answers the same question, so the port is a rule detector with no weights. It measures overlap rather than entailment and says so in its own docstring, which matters because the detector that judges support here is `groundedness` and its model does not yet do it. |
| `detect_system_prompt_leakage` | `system_prompt_leakage` | rewritten from whole-string similarity to containment. The original passes a long answer that quotes the prompt verbatim. |
| `endpoint_is_reachable` | `url_reachability` | with a deadline, a refusal to request private addresses, and 3xx counted as reachable. Upstream has no timeout at all, fetches whatever the model emitted from inside your network, and reports a redirect as unreachable. |

## Not ported

`gap` marks the ones worth building. Eight of the nine are marked, and the shape of
what is left changed on 2026-08-11: everything blocked by a rule has been built, and
what remains is blocked by a model that does not exist.

The `reason` column doubles as the requirement each would declare in `Spec.requires` if
it were built, so this table is also the backlog, sorted by what each item would cost a
caller to enable. Three left it the same day by being built: `exclude_sql_predicates`
and `valid_sql` are `sql_injection`, and `endpoint_is_reachable` is `url_reachability`.
Between them they are the two detectors outside `CORE`, and the shape of what the rest
of this list looks like once it is done.

`valid_address` is the one entry declined on grounds other than effort, and half of it
is now built as `postal_code`. It is a
wrapper around Google's Address Validation API. The network call is not the problem;
`url_reachability` makes one. The problem is that it needs a paid credential, that the
credential cannot live in a policy because policies are reviewable documents that get
hashed, and that the payload is a customer's postal address going to a named third party
under that third party's terms. A library whose `pii` detector exists to stop personal
data leaving should not ship a detector that posts it somewhere. If you want the check,
the vendor relationship already exists in your code and the call belongs there. The
local alternative that would fit here is a per-country postcode and address-shape check,
which is a data task across the 26 and a different detector from this one.

| hub validator | reason | detail | gap |
| --- | --- | --- | --- |
| `bert_toxic` | covered | `toxicity`. | no |
| `bias_check` | covered | `bias`. | no |
| `detect_jailbreak` | covered | `injection`. | no |
| `detect_pii` | covered | `pii`. Presidio is not the engine here. | no |
| `detect_prompt_injection` | covered | `injection`. Upstream calls OpenAI through the Rebuff library to answer it; the encoder here answers the same question locally. | no |
| `gibberish_text` | covered | `gibberish`. | no |
| `guardrails_pii` | covered | `pii`. | no |
| `nsfw_text` | covered | `nsfw`. | no |
| `politeness_check` | covered | `politeness`. Upstream calls a model through litellm. | no |
| `presidio_gliner_pii` | covered | `pii`. | no |
| `profanity_free` | covered | `toxicity` for the model-backed answer, `banned_terms` for a list you supply. Its own backend, `alt-profanity-check`, is an English model, so porting it would add a 26-language claim it cannot support. | no |
| `prompt_injection_detector` | covered | `injection`. Upstream scores the prompt with a second model. | no |
| `provenance_embeddings` | covered | `groundedness`. | no |
| `provenance_llm` | covered | `groundedness`. Upstream calls a model through litellm to compare an answer with its sources. | no |
| `provenance_nli` | covered | `groundedness`. | no |
| `qa_relevance_llm_eval` | covered | `topic_scope`. Upstream asks the model whether its own answer was relevant, which is a model grading itself. | no |
| `relevancy_evaluator` | covered | `topic_scope`. Upstream calls a model. | no |
| `responsiveness_check` | covered | `politeness`. Its description is the same as politeness_check's, and so is its implementation. | no |
| `restricttotopic` | covered | `topic_scope`. | no |
| `secrets_present` | covered | `secrets`, which additionally carries credential keywords in all 26 languages so its entropy rule fires outside English. | no |
| `sensitive_topics` | covered | `topic_scope`. | no |
| `similar_to_document` | covered | `groundedness`. | no |
| `toxic_language` | covered | `toxicity`. | no |
| `toxic_language_llm` | covered | `toxicity`. Upstream asks a model for the same seven categories the classifier here scores. | no |
| `unusual_prompt` | covered | `injection`. Upstream asks a model whether the prompt is tricky. | no |
| `llm_critic` | llm | grades the output with a second model. | yes |
| `logic_check` | llm | asks a model to find logical fallacies. | yes |
| `response_evaluator` | llm | calls a model through litellm. | yes |
| `saliency_check` | llm | calls a model through litellm. | yes |
| `wiki_provenance` | llm | calls a model and fetches Wikipedia while scanning. | yes |
| `llamaguard_7b` | retrain | Llama Guard is a generative model under a Meta community licence, which is not Apache-2.0 compatible, and the current 12B cannot meet a CPU budget. The capability is wanted: the plan is our own smaller model rather than a port. An Apache-2.0 alternative, gpt-oss-safeguard, was evaluated on 2026-08-12 and declined for the detector at 20B while being adopted as a corpus labeller. See the note in the document about what that settles. | yes |
| `shieldgemma_2b` | retrain | ShieldGemma is 2B under the Gemma Terms of Use, which is not Apache-2.0. Same disposition as llamaguard_7b: the capability is wanted, the weights are not usable here. Closed on 2026-08-12 as a duplicate of `moderation`, which is already catalogued for this capability as a retrain on a small Apache-2.0 base. See docs/proposed-detectors.md. | yes |
| `valid_address` | vendor | the vendor half is declined and the local half is built. It wraps Google's Address Validation API, which needs a paid credential, cannot carry that credential in a policy because policies are reviewable documents that get hashed, and sends a customer's postal address to a named third party under that party's terms. A library whose `pii` detector exists to stop personal data leaving should not ship one that posts it somewhere. What the check can answer without a vendor is now `postal_code`: whether a code is well formed for the countries the product serves, and whether it falls inside a published province or department range. Whether the address exists still needs a postal authority's database and is still not answered here. | no |

## The two moderation models

`llamaguard_7b` and `shieldgemma_2b` are the only entries whose value is entirely in
model weights this project cannot ship. Llama Guard is 7B under the Llama Community
Licence and ShieldGemma is 2B under the Gemma Terms of Use; neither is Apache-2.0
compatible, and porting the code without the weights would be shipping a shell.

The decision on 2026-08-11 was to keep the capability and train our own on a smaller
Qwen base. Two things to get right when that happens, and neither is a reason not to:

- **Pin decoding.** A generative detector declares `requires={"llm"}`, and entry 6 in
  `CLAUDE.md` still holds: greedy decoding and a fixed seed, or the same input yields
  two verdicts and the evidence record stops being evidence.
- **Give it a budget it can meet.** The encoder detectors here are 278M and cost 51 ms
  at the reference input. A 1.6B generative pass on CPU is far past the 300 ms T3
  ceiling, so it needs its own tier, its own budget, or `requires={"gpu"}`.

A classification head on that base avoids both and answers the same question. That is a
training decision rather than a library one, so it is recorded here rather than resolved
here.

## Queued: what a complete detector set would contain

This port answered "which hub validators are worth having". It did not answer "what is
missing from the detector set as a whole", which is queued after the migration.

The raw material is assembled: the `gap = yes` rows above, the `UNSUPPORTED` table in
`src/flowx_border/adapters/llm_guard_compat.py`, and the three detectors that ship
unavailable for want of published weights (`injection`, `regulated_advice`,
`groundedness`).

`InvisibleText` left that list on 2026-08-11 by being built. It was not a hub validator,
so it appears in none of the tables above, but it was the clearest gap either inventory
named and it is now `invisible_text`: bidirectional controls, tag characters and
zero-width characters, at T0, on both sides. It is the only detector whose case for T0
rests on the language list rather than on cost, since all 26 supported languages are
left to right and a bidirectional override therefore has no typographic purpose in any
text this library claims to support.
