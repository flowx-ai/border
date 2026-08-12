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
- **Not a finished set of detectors.** 15 of the 25 in the catalogue run on a fresh
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
| `pii`, `output_leakage` | 50 ms | 75 ms |
| `groundedness` | 61 ms | 300 ms |
| the seven classifiers | 151 ms | 225 ms |
| `topic_scope` | 214 ms | 300 ms |

Two things about those numbers.

**Threads are not taken by default.** At 96 tokens the same model pass costs 54.7 ms at one
thread, 29.8 at two, 17.8 at four and 12.4 at eight. The default is one, because a library
that quietly takes eight cores from the application it is embedded in is worse than a
library that is honestly slower. A policy can raise it.

**The classifiers cost three times what `pii` costs on the same base model**, and the
reason is quantisation rather than the head. Quantising every operator to INT8 moved 51 of
300 decisions, so those exports quantise the embedding matrix only and leave the transformer
in fp32: 511 MB rather than 266, and 151 ms rather than 51. A decision-safe export costs
three times a decision-changing one. Recovering the difference is open work.

A full output-side scan with everything enabled is roughly 810 ms at the reference length.
The tier system exists to keep that off the common path.

## Measured quality

Also from `docs/reference/performance.json`. **Read the support column before the score
column.**

| detector | metric | macro | worst language | examples |
|---|---|---|---|---|
| `regulated_advice` | F1 | 0.995 | 0.957 | 622 positives |
| `nsfw` | F1 | 0.976 | 0.870 | 262 positives |
| `gibberish` | F1 | 0.966 | 0.870 | 276 positives |
| `toxicity` | F1 | 0.960 | 0.400 | 104 positives |
| `injection` | F1 | 0.888 | 0.444 | 182 positives |
| `politeness` | F1 | 0.887 | 0.400 | 77 positives |
| `groundedness` | exact match | 0.882 | 0.636 | 479 evaluated |
| `topic_scope` | top-1 accuracy | 0.872 | 0.375 | not recorded |
| `bias` | F1 | 0.869 | 0.571 | 130 positives |

**Four of those rest on fewer than ten positive examples in every one of the 26 languages**:
`toxicity`, `injection`, `politeness` and `bias`, between two and seven each. Their
per-language scores are indicative rather than measured, and the JSON says so per language
rather than in a footnote. `topic_scope`'s evaluation recorded no sample sizes at all, so its
rows publish a null and say why.

`nsfw` and `gibberish` were two of that group until their corpora were rebuilt on 2026-08-11,
and what happened is the reason the support column is printed first. Neither model changed
architecture and neither gained a training trick. `nsfw` went from 52 positives to 262 and
from 0.817 to 0.976; `gibberish` from 78 to 276 and from 0.834 to 0.966. The corpora had been
9 and 11 percent positive because one generation weight was doing two jobs, so the test splits
held 2 and 3 positives per language. `nsfw` now clears ten positives per language in all 26,
and `gibberish` in 24 of 26, with Bulgarian and English at nine and flagged for it.

Maltese is absent from XLM-RoBERTa's pretraining entirely, which is worth knowing about any
score in that language. It is not, on the evidence here, what bounds one: `nsfw` scored 0.000
in Maltese while its test split held two examples, and 1.000 with perfect precision and recall
once it held ten. This README said the base model was the cause. It was the sample size.

A note on what these metrics measure. A single-label head reports exact-match accuracy
rather than F1, because precision and recall over "did the detector fire" are 1.000 by
construction when something always fires. An earlier version of this project published
1.000 for a detector whose real accuracy was 0.86 for exactly that reason.

## Detectors

25 catalogued. 24 implemented. 15 run on a fresh install with no model download, 9 are
implemented and waiting on weights that are not published yet, and 1 is not implemented.
The full table, generated from the code, is in [docs/detectors.md](docs/detectors.md).

Twelve of the 15 need nothing beyond a CPU and the base install, and work on a machine
with the network interface down:

`secrets`, `disclosure`, `invisible_text`, `banned_terms`, `system_prompt_leakage`,
`markup_injection`, `internal_domains`, `output_format`, `postal_code` and `repetition` are
rules and need no model at all. `pii` and `output_leakage` share one 266 MB model, so they
need it cached once and nothing after that.

The other three run without a model download but ask for something else, and declare it:
`sql_injection` and `json_schema` each need an optional extra, and `url_reachability` makes
an HTTP request during a scan. `deployment_notes` names them at policy load, so you find out
when you enable one rather than from a latency graph.

Eleven detectors were ported from the Guardrails Hub. Which validators went where, and the
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

1. **Thin evaluation corpora.** Covered above. Four detectors still have single-digit
   positive counts per language: `toxicity`, `injection`, `politeness` and `bias`. Two more
   did until their corpora were rebuilt, which moved them by 0.13 to 0.16 macro F1 without
   touching the models, so treat the remaining four as understated rather than as measured
   ceilings.
2. **`groundedness`'s model reads the sentence, not the source.** The detector is
   implemented and correct. The model reports 0.882 exact-match accuracy on its own test
   split, and that number does not mean what it appears to. Swapping a candidate sentence's
   source for an unrelated passage in another language leaves the verdict unchanged for four
   of its eight example types: one real paraphrase scores 0.9999 supported against its own
   source and 0.9999 against a Romanian passage about travel expenses. The corpus leaks its
   label through the candidate sentence's style, because every generation request asked for
   ten examples of one type with the type named in the prompt, so each class came out
   stylistically uniform and the model learned the style.

   What follows is that it handles paraphrases written in that generator's voice and rejects
   paraphrases written in any other, which is the case that matters, since an LLM paraphrases
   its sources in its own voice. It also needs near-exact wording: dropping two words from a
   supported restatement flips it from 0.9999 supported to 0.0002. The model is therefore not
   published, the behaviour is pinned by four tests, and the fix is a corpus where the same
   sentence appears against both a source that supports it and one that does not, so style
   cannot predict the label by construction.
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
