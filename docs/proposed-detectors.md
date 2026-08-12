# Should the remaining gaps become detectors?

A proposal, requested after the Guardrails Hub port rather than folded into it, so that the
question "should this exist" was asked separately from "can this be ported". Written 2026-08-12.

It recommended **building three**, **folding two into a detector that already exists**, and
**declining eight**, with a tier, a budget and a cost for each so the recommendation could be
argued with rather than taken on trust.

**All three were approved and built on 2026-08-12**, so the first half of this document is a
record rather than a proposal. The declines stand. What each detector actually cost, and the
two places this document was wrong, are in "What it cost" at the end.

## Where the candidates come from

Three sources, deliberately kept apart because they are different kinds of gap.

**The 8 hub validators tagged `gap = yes`.** Declined during the port for a reason that was about
the implementation rather than the capability, so the capability is still wanted. Rendered from
`detectors/guardrails_hub.py`.

**The 7 llm-guard scanners with no equivalent.** From `UNSUPPORTED` in
`adapters/llm_guard_compat.py`. These are capabilities a migrating caller had and loses, which is
a stronger signal of demand than a hub listing: somebody was using it.

It was 8 until this document was written. `InvisibleText` was listed as unsupported with a note
saying no detector reported those characters yet, and `invisible_text` had in fact shipped as a
T0 detector in CORE. That is corrected, and it is worth recording as the cheapest finding here: a
migration table that understates what exists sends people away for something they already have.

**Not included: the three that ship unavailable.** `injection`, `regulated_advice` and
`groundedness` are already catalogued, already counted against the total, and need weights or a
corpus rather than a decision about whether to exist. `moderation` is the same. They are not
candidates and adding them here would double-count them.

## What a budget costs, so the numbers below mean something

Every figure is measured, from `tests/test_budgets.py` and the tables in CLAUDE.md, at the 87
token reference input on one thread.

| shape | measured | budget it needs |
|---|---|---|
| a rule over folded text | 0.02 to 0.36 ms | 5 ms, T0 or T1 |
| stdlib string work, `difflib` | 0.09 ms | 5 ms, T1 |
| a parse tree, `sqlglot` | 0.31 ms | 5 ms, T1, `dependency` |
| an XLM-R encoder pass | 151 ms | 225 ms, T1 or T2 |
| a bi-encoder against a taxonomy | 214 ms | 300 ms, T3 |
| an HTTP request | a deadline, not a measurement | 3000 ms, T3, `network` |
| a generative model on CPU | far past any tier | no budget it can meet |

That last row is the one that decides most of this document. A 0.6B generative pass does not fit
a 300 ms CPU budget, and the smallest thing that behaves like a judge is larger than that. Any
candidate whose capability requires generation is therefore a `requires={"llm", "gpu"}` detector
or it is nothing, and every one of those is declined below on that basis rather than on taste.

## Recommended: build three

### 1. `summary_support`, from `extracted_summary_sentences_match` (built)

**T1, 5 ms, no weights, CORE.** The one candidate that is free.

The hub validator calls OpenAI to ask whether a summary's sentences appear in the source. The
question does not need a model: it is whether each sentence of the output has a near match in the
source text, which is `difflib` over sentence pairs. `repetition` already does exactly this shape
of comparison at 0.09 ms, and `multilingual.sentences` already splits sentences in 26 languages.

The honest limit, and it must be in the docstring: this measures overlap, not entailment. A
summary that paraphrases well scores badly and a summary that copies a sentence and negates it
scores perfectly. It is a cheap check for extractive summaries and it is not `groundedness`.
Given what happened to `groundedness`, whose model turned out to read style rather than compare,
a detector that is honest about measuring overlap is worth more than one that implies more.

**Cost:** half a day. No corpus, no GPU, no API spend. Fixtures in 26 languages, which for a
`difflib` detector is a data task of writing 26 summary and source pairs.

### 2. `code_present`, from `BanCode` and `Code` (built)

**T1, 5 ms, no weights, CORE.** Two llm-guard scanners, one detector.

A migrating caller loses both today. `sql_injection` parses generated SQL and says nothing about
Python in a prose answer, or about whether a user pasted a shell command. The capability is
"does this text contain code", and for the common cases it is a rule: fenced blocks, shebangs,
import and function-definition shapes across the handful of languages that matter, indentation
plus punctuation density.

It will be wrong at the margin, and the margin should be a policy option rather than a hidden
threshold. Prose about programming trips any such rule, which is the same false positive
`sql_injection` has and the same answer: report what fired, let the policy decide.

Do **not** reach for a model here. A CodeBERT-shaped classifier is another 151 ms encoder for a
question a regex answers at 0.2 ms, and it would need a 26 language corpus of prose-about-code
to avoid the obvious false positive.

**Cost:** two days, most of it fixtures. The languages a caller cares about are not the 26 human
ones, which is worth saying out loud in the catalogue entry.

### 3. `token_limit`, from `TokenLimit` (built)

**T1, 5 ms, `dependency`, outside CORE.** Small, and only worth it because the reason it was
declined is fixable.

The declined note says a token limit depends on the tokenizer of the model you are calling, which
this library does not know. That is true and it is not a reason to refuse: it is a reason to make
the policy name the tokenizer. `output_format` counts graphemes and words, which is a different
number from the one a caller asked about, and quietly reporting a different number is worse than
not answering.

So: the policy names a tokenizer, the detector loads it through `tokenizers`, counts, and reports.
Unconfigured it reports `token_limit_unconfigured` rather than guessing, like `banned_terms` does
with no term list.

**Cost:** a day. The interesting part is refusing to fall back to a word count when the tokenizer
is absent.

## Recommended: fold two into `moderation`

`llamaguard_7b` and `shieldgemma_2b` are the same capability under two licences this project
cannot use, and CLAUDE.md already records the disposition: a retrain on a small Apache-2.0 base
rather than a port. `moderation` is already in the catalogue for exactly that, at T2 with a 150 ms
budget, pipeline validated and corpus outstanding.

**So the recommendation is to close both as duplicates of `moderation` rather than to open them as
candidates**, and to note in `guardrails_hub.py` that this is where they went. Two things still
have to be settled before `moderation` is built, and they are the same two that stopped
`semantic-mapper`:

- A generative model reading a policy and writing a verdict is an LLM call inside a detector, which
  default 4 rules out at any size. The answer is a classification head on a small base, and the
  cost of that answer is that it cannot explain itself the way Llama Guard can.
- 150 ms is the current budget and a 0.6B generative pass will not meet it. If `moderation` becomes
  a classification head on the Qwen3-0.6B base, the budget needs the same treatment the seven
  classifiers got: measure it, then set it, in its own commit.

## Recommended: decline eight, with the reason

### The five LLM-as-judge validators

`llm_critic`, `logic_check`, `response_evaluator`, `saliency_check`, `wiki_provenance`.

All five ask a second model to grade something. Ported faithfully they are
`requires={"llm", "gpu"}` detectors with no budget they can meet on the reference target, and
`response_evaluator` is not even a detector: it is a framework for writing one, which belongs in
the caller's code rather than in a catalogue that promises a tier and a budget per entry.

`wiki_provenance` additionally fetches Wikipedia during a scan, so it is `network` as well, which
puts a third party in the latency path of every scan and makes their outage yours. `url_reachability`
already carries that cost and is disabled in both shipped policies for it.

There is a real capability behind `logic_check` and `saliency_check`, and the honest thing is that
this library cannot deliver it at the reference target rather than that it is not worth having.
If the target ever admits a GPU, revisit them together.

### `malicious_urls`

Needs a URL reputation feed. Not a model problem: a detector is only as good as the feed, the feed
is a subscription and a third party in the scan path, and shipping one that silently has no feed
would be the no-op this project refuses. `url_reachability` answers the narrower question the
library can answer honestly.

### `language` and `language_same`

Language identification. Every detector here works in 26 languages rather than gating on which one
a text is in, so identification is not needed internally, and as a caller-facing check "is this
Bulgarian" is a different product from "is this safe". A small classifier would cost 151 ms for a
question a caller can answer with `langdetect` in their own code at a fraction of that.

Worth a second look only if a caller wants "reply in the language the user wrote in" enforced,
which is a governance question rather than a safety one, and `output_format` is the nearer home.

### `sentiment`

`politeness` is the neighbour and it is not the same thing, which the declined note already says.
Sentiment is a product analytics measure rather than a guardrail: knowing an answer was negative
does not tell an operator whether to block it. Declined as answering no security or governance
question, which is the bar entry 3 in CLAUDE.md sets, and the one detector that fails it
(`output_format`) exists only because it gave sixteen hub shape validators one destination.

## What it cost

The projection below was written before any of the three existed. The measured column is
what `benchmarks/collect.py` and `tests/test_budgets.py` report now.

| | detectors | CORE | that run with no download |
|---|---|---|---|
| before | 25 catalogued, 24 implemented | 22 | 15 |
| projected | 28 catalogued, 27 implemented | 24 | 18 |
| measured | 28 catalogued, 27 implemented | 26 | 18 |

The one number that missed is CORE, 26 rather than 24, and the reason is the first of two
things this document got wrong.

**`token_limit` is in CORE, not outside it.** This document put it outside with
`requires={"dependency"}`, on the assumption that loading a tokenizer meant a new package.
`tokenizers` has been in the base install since phase 0, so the detector needs nothing and
declares nothing. The projection was two short because it also counted `code_present` out
on the same reasoning.

**The interesting part of `code_present` was not the fixtures.** This document costed it at
two days, most of it fixtures, and predicted the hard part would be the false positive on
prose about programming. The fixtures were quick. What took the thought was that every
pattern has to be anchored at the start of a line: without the anchor, "Our function is to
keep your money safe" reports as a function definition, which was measured rather than
imagined. The anchor costs a definition quoted inside a sentence, and that trade is now
pinned by a test that asserts the miss and argues for it.

Two things the document got right and are worth keeping for the next candidate.
`summary_support` genuinely was half a day and genuinely needed no corpus. And the
recommendation to fold `llamaguard_7b` and `shieldgemma_2b` into `moderation` rather than
open them as candidates survived a direct challenge on 2026-08-12, when `gpt-oss-safeguard`
was raised as an Apache-2.0 alternative: it answers the licence objection and makes the
generative-in-a-detector and CPU-budget objections worse, so the disposition did not move.
See CLAUDE.md for that record.

**`token_limit` also needed a decision this document did not anticipate.** The declined note
said a token count depends on a tokenizer the library does not know, and the answer here was
"the policy names it". That is necessary and not sufficient: a named but unpinned tokenizer
still makes the count unreproducible, which default 6 forbids. So the policy must name a
local file, whose hash becomes the reported revision, or an id already carrying a commit.
A bare Hugging Face repo id is refused.

The five LLM judges and the three feed-or-model gaps stay declined and stay recorded, which is the
same treatment the 33 declined validators got: the reason is written down so that the next person
to ask does not have to rediscover it.
