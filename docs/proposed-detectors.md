# Which detectors should complete the set

Queued by the owner on 2026-08-11, deliberately after the Guardrails Hub port rather than
folded into it, so that the question is "what is missing" rather than "what did we not get
round to porting". Written 2026-08-16.

The output is a proposal with a tier and a budget each, not a set of new detectors. Nothing
here is built.

## Where the candidates come from

Three lists, assembled rather than invented:

- the seven `gap = yes` rows of the declined table in
  `docs/porting-guardrails-validators.md`, being hub validators whose capability is real
  and whose implementation was refused
- the nine `UNSUPPORTED` entries in `adapters/llm_guard_compat.py`, being llm-guard
  scanners a migrating caller asks for and does not get
- the three detectors that ship unavailable for want of published weights

The third list is not a gap in the set, it is work in flight, so it is out of scope here.

## The bar

CLAUDE.md sets it and it has not moved. A new detector must work in all 26 languages with
fixtures for each, meet its tier's budget at the reference input, and never silently do
nothing. The count cap was dropped on 2026-08-11; those three rules are what stop breadth
becoming shallowness, so they matter more now than when there was a cap.

One further test applies to everything below, from the same file: **prefer a classification
head on a small base over a generative model, and say why when you do not.** Five of the
seven `gap = yes` rows are a second LLM grading the first one, and all five fail defaults 4
and 6 as written. They are not proposed as `requires={"llm"}` detectors; where the
capability is worth having, it is proposed as an encoder.

## Proposed, in the order I would build them

### 1. `language_id`, T1, 5 ms

**Two llm-guard scanners map to it and nothing else covers it.** `Language` asks whether
text is in an expected language and `LanguageSame` whether the prompt and the answer agree.
Both are `UNSUPPORTED` today, and the shim can only say so.

The reason this is first is not the migration. A library that claims 26 languages and
cannot say which one it is looking at has a hole in its own story: every per-language score
in this repository was computed against a label the corpus asserted, never against one
measured at scan time. A caller who wants "answer in the language the user wrote in" has no
way to check, and that is a real governance question rather than a convenience.

Cheap: a character n-gram model over 26 known languages is kilobytes and microseconds, not a
transformer. The budget is the T1 rule-detector ceiling because it should cost nothing.

Worth naming as a risk: language identification is unreliable on short text, and a detector
that reports `uncertain` on a five-word answer is correct and will be read as broken. It has
to report a confidence and the policy has to have a floor.

### 2. `pii_reidentification`, T2, 225 ms

**Nothing in the hub or in llm-guard proposes this, which is why it is second rather than
absent.** `pii` finds an entity; nothing asks whether a combination that contains no entity
still identifies somebody. A postcode with a date of birth and a job title is the standard
example, and the library currently returns `allow` on it with an evidence record saying
every check passed.

This is the one candidate that answers a question the existing set cannot ask at all, and
it is squarely a governance question rather than a security one. It is also the hardest to
get right, and I would not build it before `language_id` on that basis.

An encoder over the sentence with a quasi-identifier taxonomy, so a classification head
rather than a generative pass. T2 and 225 ms puts it beside the other encoders.

### 3. `sentiment`, T2, 225 ms

`Sentiment` is `UNSUPPORTED` and the shim says the nearest thing is `politeness`, which is
not the same: a furious complaint can be impeccably polite. A migrating caller who scanned
for sentiment gets nothing today.

Straightforward, well understood, and the corpus work is the same shape as the five
classifiers already trained. Third rather than first because it is the most replaceable:
plenty of callers already have one.

### 4. `url_reputation`, T3, 3000 ms, `requires={"network"}`

`MaliciousURLs` is `UNSUPPORTED`, and the shim is precise about why: `url_reachability`
asks whether a link answers, which is a different question from whether it should be
followed. An LLM inventing a plausible domain that somebody has since registered is a real
failure mode.

Proposed reluctantly and fourth, because it inherits everything `url_reachability` already
carries: a third party in the latency path, their outage becoming yours, and a reputation
feed that is itself a claim the library cannot verify. Same tier, same budget, same
`requires`, and it must be disabled by default in both shipped policies.

## Considered and not proposed

**The five LLM-grader rows.** `llm_critic`, `logic_check`, `response_evaluator`,
`saliency_check` and `wiki_provenance` all grade an answer with a second model.
`groundedness` already covers the part of this that is checkable against a source, and it
has failed four candidate models this week precisely because the honest version is hard.
The rest is a model's opinion of another model's output, which is not evidence and does not
belong in a record that claims to be auditable. `wiki_provenance` also fetches while
scanning, which breaks default 1.

**`llamaguard_7b` and `shieldgemma_2b`.** Already settled in CLAUDE.md and unchanged: the
licences bar redistribution, the sizes bar the budget, and a model that reads a policy and
then reads attacker-controlled text is itself an injection surface. `moderation` is the
answer to this row and is in flight.

**A `reading_time` or `regex` detector.** Both are `UNSUPPORTED` in the shim only because
they map onto `output_format` options rather than because the capability is missing. That is
a mapping gap in the adapter, worth an hour, and not a detector.

## What I would want before committing to any of it

A count of which of these anyone has asked for. Every candidate above is argued from the
inside: from a table of things we declined, a table of things a shim cannot translate, and
my own reading of what the set cannot ask. That is the same shape as the failure this
project keeps recording, where a measurement drawn from the same source as the thing it
measures agrees with itself.

`language_id` I would build regardless, because the 26-language claim rests on it.
