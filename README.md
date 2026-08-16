# flowx-border

An embeddable Python library that inspects the text going into and coming out of an LLM,
and returns a structured decision plus an audit-grade evidence record. It ships its own
open-weight detection models and runs them on CPU.

Two functions. No gateway, no proxy, no wrapper around your model call.

```python
from flowx_border import load_policy, scan_input, scan_output

policy = load_policy("policies/default.yaml")

decision = scan_input(user_text, policy)
if decision.verdict == "block":
    return refusal(decision.evidence.record_id)

answer = your_llm(decision.text)

checked = scan_output(answer, policy)
return checked.text, checked.evidence
```

## What this is not

Read this part first, because it is the part most likely to be assumed wrong.

- **Not a gateway or a proxy.** It does not sit in front of your model, hold your API key,
  or make the call for you. You call your model; this inspects the text either side.
- **It does not make anyone compliant with anything.** It produces an auditable record of
  which checks ran and what they found. Obligations under any AI regulation sit with the
  provider or deployer of a system, not with a library inside it. Runtime checks observe a
  narrow slice: whether a required disclosure is present in text, and whether the controls
  a policy configured actually ran.
- **Not a replacement for a security review.** A detector that finds nothing is evidence
  that these checks found nothing, and nothing more.
- **Not a finished set of detectors.** 19 of the 29 in the catalogue run on a fresh
  install. The rest are counted, named, and explained below rather than implied to work.
- **Not calibrated for your data.** Every quality number here was measured on synthetic
  corpora built for this project, and most of them rest on very few examples per language.
  The sizes are published beside the scores so you can judge them.

## Install

```sh
pip install flowx-border
```

Python 3.11 or newer. The base install needs `pydantic`, `pyyaml`, `onnxruntime`,
`tokenizers`, `huggingface-hub` and `cryptography`. Two optional extras exist because two
detectors need a parser: `flowx-border[sql]` for `sql_injection` and `flowx-border[schema]`
for `json_schema`. A detector whose extra is missing is absent from the registry rather
than degraded to a pass, and a policy that enables it is refused at load.

Model weights are fetched once, on first load, and cached. After that a scan needs no
network. `tests/test_offline.py` asserts that with the interface down.

## The two functions

```python
decision = scan_input(text, policy, ctx=None)
decision = scan_output(text, policy, ctx=None)
```

Both return a `Decision`:

```
verdict         "allow" | "redact" | "block" | "flag"
text            possibly redacted or rewritten
original_text   what came in
findings         list[Finding], each with a detector, label, score, span and action
evidence        EvidenceRecord
elapsed_ms      float
tiers_run       which tiers ran, which is not always all of them
```

`ctx` carries what the text does not say: `sources` for groundedness, an optional
`locale` hint, and free metadata. It is optional, and the detectors that need it report
that they could not run rather than passing quietly.

## The policy file

Policy is data, never code. That is a requirement rather than a default, for two reasons:
`policy_hash` in the evidence record only pins behaviour if the document fully determines
behaviour, and a compliance officer who does not write Python has to be able to read it.

```yaml
policy_id: default
version: 1

fail_mode:
  T0: closed          # a detector that errors blocks the scan
  T1: open            # a detector that errors is recorded and the scan continues
  T2: open
  T3: open

detectors:
  secrets:
    enabled: true
    on_fail: redact
  pii:
    enabled: true
    on_fail: redact
    threshold: 0.5
    options:
      entities: [email, phone, iban, card, national_id, person]
  toxicity:
    enabled: true
    on_fail: flag
  groundedness:
    enabled: false
    always: true      # T3 only: run even when no lower tier flagged
```

Detectors run in tiers. T0 always runs and cannot be disabled. T1 and T2 run on the
standard path, and T2 may be disabled per policy. T3 runs only when a lower tier flags at
or above its threshold, or when the policy sets `always: true`, and the record says which
of those happened.

`registry.deployment_notes(policy)` returns one line per thing a policy asks of the
machine beyond a CPU and the base install: a network call, an accelerator, a generative
model, a dependency. It returns lines rather than raising, because needing a GPU is not an
error, and a caller who wants it to be fatal can treat a non-empty result that way.

## The evidence record

Every scan produces one. It never contains raw user text, only hashes, and there is a test
for that.

```
record_id         UUIDv7, monotonic within a process
timestamp         RFC 3339, UTC
direction         "input" | "output"
policy_id         from the document
policy_hash       sha256 of the resolved policy
library_version
detectors         one attestation each: id, model id, revision, weights sha256
input_hash        sha256 of the original text
verdict
finding_summary   detector_id, label, score, action
signature         Ed25519 over the canonical JSON, or null
```

Serialisation is canonical JSON, sorted keys and no whitespace, so a hash computed on one
machine matches a hash computed on another.

The library never holds a signing key. You pass a signer, it signs, and verification takes
a public key:

```python
from flowx_border.evidence import sign_record, verify_record

signed = sign_record(decision.evidence, your_private_key)
assert verify_record(signed, your_public_key)
```

A scan is deterministic given the same input and the same model revisions. No sampling, no
temperature, no clock inside a scan. A record that cannot be reproduced later is a log line
with a signature on it.

## Measured latency

Every figure below comes from `benchmarks/collect.py`, which writes
`docs/reference/performance.json`, and every ceiling is asserted in `tests/test_budgets.py`.
Rerun it yourself:

```sh
uv run python benchmarks/collect.py --artifacts <dir>
uv run pytest -q tests/test_budgets.py
```

The reference input is 87 tokens and 396 characters of Romanian prose with no entities in
it, so this measures the cost of looking rather than the cost of finding. One thread,
CPUExecutionProvider, INT8 weights, Apple M-series laptop, 2026-08-11. p95, best of three
rounds.

| detector | p95 | budget |
|---|---|---|
| the eleven rule detectors | 0.01 to 2.02 ms | 1 to 5 ms |
| `groundedness` | 61 ms | 300 ms |
| the seven classifiers | 151 ms | 225 ms |
| `pii`, `output_leakage` | 153 ms | 225 ms |
| `topic_scope` | 214 ms | 300 ms |

Two things about those numbers.

**Threads are not taken by default.** At the 87-token reference input the same model pass
costs 157.32 ms at one thread, 79.50 at two, 42.99 at four and 25.63 at eight. The default
is one, because a library that quietly takes eight cores from the application it is
embedded in is worse than a library that is honestly slower. A policy can raise it.

**Cost is linear within a window and steps at each boundary.** A window holds 94 content
tokens, so 94 tokens is one forward pass and 95 is two: about 33 ms more for one more
token. Within a window the slope is 1.66 ms per token, and a document of n tokens costs
roughly `ceil(n / 94)` passes. Both figures come from `benchmarks/latency_sweep.py`, which
refuses to run on a busy machine and cross-checks itself at the reference length against
the budget suite's independently recorded 153 ms.

**A decision-safe INT8 export costs three times a decision-changing one, and every model here
now pays it.** Quantising every operator moved 51 of 300 decisions, so these exports quantise
the embedding matrix only and leave the transformer in fp32: 511 MB rather than 266, and 151 ms
rather than 51. Measured on 2026-08-12, the recipes in between are no better: anything touching
MatMul moves probabilities by a p99 of 0.98, which is a different model rather than a quantised
one. Static quantisation or quantisation-aware training might recover it; op selection does not.

`pii` and `output_leakage` joined that bill on 2026-08-12. They ran at 51 ms on a 266 MB
artifact that had never been checked against its own weights, and on 120 texts it lost an entity
on 13 of them, which is a hole in a redaction the caller cannot see. Re-exported with the same
recipe as the classifiers it loses none, at 153 ms. A PII redactor that silently misses an
entity is worse than a slow one.

A full output-side scan with everything enabled is roughly 810 ms at the reference length.
The tier system exists to keep that off the common path.

## Measured quality

Also from `docs/reference/performance.json`. **Read the support column before the score
column.**

| detector | metric | macro | worst language | examples |
|---|---|---|---|---|
| `regulated_advice` | F1 | 0.995 | 0.957 | 622 positives |
| `nsfw` | F1 | 0.934 | 0.600 | 259 positives |
| `injection` | F1 | 0.970 | 0.727 | 357 positives |
| `gibberish` | F1 | 0.966 | 0.870 | 276 positives |
| `politeness` | F1 | 0.962 | 0.788 | 392 positives |
| `toxicity` | F1 | 0.992 | 0.950 | 518 positives |
| `bias` | F1 | 0.977 | 0.824 | 264 positives |
| `topic_scope` | top-1 accuracy | 0.865 | 0.375 | 175 evaluated |

`groundedness` has no row because no model for it is adopted, and the one that used to
score here was measuring its own generator. See the second entry under what is weak.

**The support column is why this table is ordered by it and not by score.** Six of these
detectors had their corpora rebuilt over 2026-08-11 and 12, and no model changed architecture
or gained a training trick. Only the data underneath them moved:

| detector | positives | macro F1 | worst language |
|---|---|---|---|
| `nsfw` | 52 to 262 | 0.817 to 0.976 | 0.000 to 0.870 |
| `injection` | 182 to 355 | 0.889 to 0.969 | 0.444 to 0.867 |
| `gibberish` | 78 to 276 | 0.834 to 0.966 | 0.400 to 0.870 |
| `politeness` | 77 to 392 | 0.887 to 0.962 | 0.400 to 0.788 |
| `bias` | 130 to 398 | 0.869 to 0.957 | 0.571 to 0.867 |
| `toxicity` | 104 to 419 | 0.960 to 0.959 | 0.400 to 0.727 |

The cause was one generation weight doing two jobs: it set both the corpus prior and the
absolute positive count, so the training loss corrected the prior twice while per-language
support stayed at two to seven examples. `toxicity` is the useful case to read carefully. Its
macro did not move, because 0.960 was already close to right; what moved is the tail, and the
old figure was an estimate on four positives per language rather than a measurement.

**`toxicity` is resolved, and it took a third attempt.** Its row above said 0.960 for a long
time because the rebuilt model existed and its INT8 export was refused by the decision-flip
gate at a margin of 0.0687 against a 0.02 band, so the previously verified model kept
shipping: a better number that cannot be exported safely is not a number this library will
publish.

The corpus was regenerated on 2026-08-14 with the shared mundane registers and length bands,
and the model retrained on it exports cleanly at 0/300 decisions changed. So this row moved
for the reason the whole exercise predicted, which is worth stating because it was an open
question rather than a foregone one:

| | before | after |
|---|---|---|
| mean per-language F1 | 0.960 | 0.992 |
| worst language | 0.400 | 0.950 (`sv`) |
| positives per language | about 4 | 197 to 209 |
| INT8 flip gate | refused at 0.0687 | passed, 0/300, max drift 0.0432 |

The support column is the one to read. At four positives per language a score is an estimate
that moves by a quarter when one example changes; at two hundred it is a measurement. That is
why this detector was described here as understated rather than as a ceiling, and it is why it
is no longer on that list.

`bias` moved the same way on the same day, 0.957 to 0.977, and needed only a retrain: its
corpus already carried the bands and the mundane registers from 2026-08-13, so the corpus was
fixed and nothing had been trained on it.

**`nsfw`'s 0.976 in the table above is the rebuild, and it is not what ships.** It was
superseded twice: by a retrain on 2026-08-13 scoring 0.918, and by another on 2026-08-14
scoring 0.934, which is the artifact the library loads. The first table shows the shipped
figure; this one shows what the first corpus rebuild bought, because that is what the
paragraph is about.

Each retrain was adopted for behaviour rather than for score, which is the thing to
understand about this row. The measurement that decided both is twenty ordinary business
sentences in ten languages, run through `scan_output` with the shipped policy:

| artifact | fires on ordinary prose |
|---|---|
| the rebuild, at 0.95 | 11 of 20, median score 0.9845 |
| 2026-08-13, at 0.81 | 1 of 20, and that one a `block` |
| 2026-08-14, at 0.76 | 0 of 20 |

The last row holds at 0.81, at 0.76 and at the neutral 0.5, so the margin is in the model
rather than in the threshold. `nsfw` ships `on_fail: block`, so a false positive here refuses
a real answer, which is why this axis outranks macro F1 for this detector.

The 2026-08-14 model is also better on score, at 0.934 against 0.918, so no trade was needed
in the end. Its worst language is Maltese at 0.600 on nine test positives, which is noise at
that size rather than a finding.

`topic_scope`'s evaluation recorded no sample sizes until 2026-08-12, which made it the one
detector here whose numbers could not be weighed at all. They can now, and they rest on 6 to 8
examples per language, so all 26 are flagged as thin. Its figure also moved from 0.872 to 0.865
because it is now measured on the INT8 artifact that ships rather than on the torch checkpoint.

Worth knowing about that detector separately: its test split contains 78 out-of-taxonomy
examples that nothing scores, so no number here describes whether it rejects input belonging to
no node, which is half of what it is for.

`gibberish` clears ten positives per language in 24 of 26, with Bulgarian and English at nine
and flagged for it.

Maltese is absent from XLM-RoBERTa's pretraining entirely, which is worth knowing about any
score in that language. It is not, on the evidence here, what bounds one: `nsfw` scored 0.000
in Maltese while its test split held two examples, and 1.000 with perfect precision and recall
once it held ten. This README said the base model was the cause. It was the sample size.

A note on what these metrics measure. A single-label head reports exact-match accuracy
rather than F1, because precision and recall over "did the detector fire" are 1.000 by
construction when something always fires. An earlier version of this project published
1.000 for a detector whose real accuracy was 0.86 for exactly that reason.

## Detectors

29 catalogued. 28 implemented. 19 run on a fresh install with no model download, 9 are
implemented and waiting on weights that are not published yet, and 1 is not implemented.
The full table, generated from the code, is in [docs/detectors.md](docs/detectors.md).

Thirteen of the 16 need nothing beyond a CPU and the base install, and work on a machine
with the network interface down:

`secrets`, `disclosure`, `invisible_text`, `banned_terms`, `system_prompt_leakage`,
`markup_injection`, `internal_domains`, `output_format`, `postal_code`, `repetition` and
`summary_support` are rules and need no model at all. `pii` and `output_leakage` share one 266 MB model, so they
need it cached once and nothing after that.

The other three run without a model download but ask for something else, and declare it:
`sql_injection` and `json_schema` each need an optional extra, and `url_reachability` makes
an HTTP request during a scan. `deployment_notes` names them at policy load, so you find out
when you enable one rather than from a latency graph.

Twelve detectors were ported from the Guardrails Hub. Which validators went where, and the
reasons the other 34 were declined, are in
[docs/porting-guardrails-validators.md](docs/porting-guardrails-validators.md), rendered
from the code so the two cannot drift.

**A detector never silently does nothing.** Unconfigured, unavailable and uncomparable are
findings it reports, not conditions it passes through. `banned_terms` with no term list
says so. `groundedness` with no sources says so. A policy that asks a missing detector to
block or redact is refused at load rather than allowing text through as if it had been
checked, because a silent no-op in a security library is a vulnerability.

## Languages

26: the 24 official languages of the EU, plus Turkish and Azerbaijani. Every detector has
fixtures in all 26, and model-backed detectors report per-language numbers rather than one
aggregate, because an aggregate hides the tail and the tail is the point.

Where a language underperforms, the number is published rather than the language dropped.
`piiguard` was trained on 9 of the 26 (`en`, `ro`, `bg`, `hu`, `sl`, `hr`, `de`, `it`,
`fr`); the other 17 are untested rather than covered, and the per-language table says so.

## Limitations

The honest list, in rough order of how likely each is to matter to you.

1. **Thin evaluation corpora, in three places rather than six.** Corpus size was the binding
   constraint and six detectors were rebuilt, which is the table above. Three still have at
   least one language with fewer than ten positive examples: `injection` in one, `gibberish`
   in two, and
   `toxicity` in all twenty-six, because the model that ships for it is the one from before its
   rebuild. Beyond that, every quality figure here was measured on synthetic corpora generated
   for this project, and one of them turned out to be measuring the generator rather than the
   task, which is the next entry. Read the support column, and treat these as internal figures
   rather than as benchmarks against anyone else's.
2. **`groundedness` ships unavailable, and no model for it is adopted.** The detector is
   implemented and correct; what is missing is a model good enough to publish. Three have
   been trained and none adopted, which is why it has no row in the quality table above.

   The first leaked its labels through style. It reported 0.882 exact-match accuracy on its
   own test split, and that number was measuring the generator rather than the task:
   swapping a candidate sentence's source for an unrelated passage in another language left
   the verdict unchanged for four of its eight example types, and one real paraphrase scored
   0.9999 supported against its own source and 0.9999 against a Romanian passage about
   travel expenses. Every generation request had asked for ten examples of one type with the
   type named in the prompt, so each class came out stylistically uniform and the model
   learned the style. **That 0.882 was published here until 2026-08-15**, with this caveat
   beside it, which is one caveat further away than a disqualified number should be.

   The corpus was then rebuilt as source-side pairs: one candidate sentence, two different
   sources, opposite labels, so the candidate text is byte-identical across a pair and style
   cannot carry the label by construction. That closed the leak, measured rather than
   assumed, and the current corpus is 16,196 examples over 26 languages.

   The model trained on it is better on every aggregate and is still not adopted, for one
   reason worth stating plainly. Against a source saying withdrawals incur a fee for twelve
   months and are free only after, the candidate "Withdrawals are free from the day the
   account opens" scores supported at 0.9906. That is a clear temporal contradiction called
   grounded, and for a detector whose whole job is noticing that a claim is not carried by
   its source, a confident false `supported` is the worst failure available. It is worse
   than what it trades against, since the other two verdicts both mean "not grounded" and
   cost a caller caution rather than a missed contradiction.

   The behaviour is pinned by tests, and those tests are not relaxed to let a model pass.
3. **`piiguard` covers 9 of 26 languages** and was exported before the decision-flip gate
   existed, so its latency and quality numbers come from a file held to a weaker standard
   than the nine trained later.
4. **English national IDs are not checksum validated.** The training generator labels the
   `en` locale United Kingdom but uses a German algorithm as a generic numeric fallback. A
   real UK National Insurance number carries no checksum, so a fallback is defensible, but
   do not read the `national_id` label as verified for English.
5. **Sentence splitting has no abbreviation list.** An abbreviation ending in a full stop
   splits a sentence in two, in every language. German `z.B.`, Hungarian `pl.` and English
   `e.g.` all do it, so a per-sentence count is right for prose and slightly high for text
   full of abbreviations. Decimals are handled.
6. **`topic_scope` compares meanings, it does not reason about them.** It scores cosine
   similarity between the input and each taxonomy node. It can tell you the nearest node
   and how near; it cannot tell you why.
7. **One detector answers no security question.** `output_format` checks shape assertions
   from the policy. It exists so that sixteen hub shape validators have one destination
   instead of sixteen, and it says so in its own docstring.

## Licence

Apache-2.0. Every source file carries the SPDX header.
