# CLAUDE.md

Standing context for this repository. Read this before every task.

## What this project is

An embeddable Python library that inspects the text going into and coming out of an
LLM, and returns a structured decision plus an audit-grade evidence record.

It ships its own open-weight detection models. It is not a gateway, not a proxy,
not an agent framework, and it does not wrap the LLM call.

Name: `flowx-border`, decided 2026-08-10, previously the working name `flowx-guard`.
Distribution name `flowx-border`, import name `flowx_border`. Even though the name is
settled, keep it out of the source: it belongs in `pyproject.toml` and the top-level
package directory, nowhere else.

## Current state, read this before looking for files

Phase 0 landed on 2026-08-10. What exists: `pyproject.toml`, the CI workflow,
`types.py`, `detectors/base.py`, the three stub public functions, and the tests for
those. What does not exist yet: the policy loader, the engine, every detector, the
model runtime, the adapters, the benchmarks, and the README. The rest of the "Repo
layout" section below is still the target, not the present.

**Phase 1 is next**, the policy layer and the engine. `scan_input`, `scan_output` and
`load_policy` raise `NotImplementedError` until it lands.

`BUILD_PLAN.md` is the sequencing document: seven phases, each with a paste-ready
prompt and a definition of done. Before starting work, find the lowest phase whose
definition of done does not yet hold, and do that one. Rules from that file that
matter across sessions:

- One phase per session. Do not run two phases in one session.
- Check the definition of done yourself rather than trusting a summary.
- Commit at the end of each phase, tagged `phase-N`, so a bad phase is one revert.

Two deliberate deviations from the specified core types were made in phase 0 and are
open for reversal on instruction:

- `finding_summary` is `tuple[FindingSummary, ...]` rather than `list[dict]`. The
  serialised JSON is unchanged, a list of objects with exactly `detector_id`, `label`,
  `score`, `action`. It is typed because the no-raw-text invariant cannot be asserted
  about a free `dict`.
- `detectors` is a tuple for the same reason `EvidenceRecord` is frozen: a mutable
  list inside an audit artifact is not immutable in any useful sense.

## The entire public API

```python
from flowx_border import scan_input, scan_output, load_policy

policy = load_policy("policy.yaml")
decision = scan_input(text, policy, ctx=None)
decision = scan_output(text, policy, ctx=None)
```

Two functions. If a task appears to require a third public entry point, stop and
ask before adding it. Everything else in the package is an implementation detail
or an adapter.

## Non-negotiable constraints

1. **No network calls at scan time.** Model weights are fetched once at install or
   first load and cached. `scan_input` and `scan_output` must work with the network
   interface down. There is a test that asserts this. Do not weaken it.
2. **CPU is the reference target.** Every detector must be usable on CPU within its
   stated latency budget. GPU is an optimisation, never a requirement.
3. **The detector set grows on instruction, and only on instruction.** It was fixed at
   eight for v1. On 2026-08-10 the owner explicitly lifted that, twice and in writing,
   to add five more: toxicity, NSFW, bias, gibberish and politeness, derived from the
   Guardrails Hub validator set. So v1 is thirteen detectors.

   The original reasoning is preserved here because it has not been refuted, only
   overruled: breadth is how the predecessor projects died, and toxicity specifically
   was the example this file used to name as commodity. Anyone reading this later should
   know the tradeoff was made deliberately rather than drifted into. The tier budgets and
   the per-language reporting rules are what stop breadth from becoming shallowness, so
   they matter more now, not less: a thirteenth detector that misses its budget or ships
   without a per-language table is worse than no thirteenth detector.

   A fourteenth still needs an explicit instruction.
4. **No LLM calls inside detectors.** Detectors are rules, NER models, or small
   classifiers running locally. A detector that calls a hosted model is out of scope.
5. **Policy is data, not code.** Policy lives in YAML validated by a Pydantic schema.
   There is no Python callback in the policy file. A compliance officer who does not
   write Python must be able to read and review a policy.
6. **Deterministic given the same inputs and model revisions.** No sampling, no
   temperature, no time-dependent behaviour inside a scan.
7. **Dependencies are expensive.** Do not add a runtime dependency without asking.
   The current allowed runtime set is: `pydantic`, `pyyaml`, `onnxruntime`,
   `tokenizers`, `huggingface-hub`, `cryptography`. Anything else needs approval.

## Detector set (fixed for v1)

**The reference input, without which no budget below means anything.** 87 tokens of
prose, 396 characters, one thread, CPU execution provider, INT8 weights. Measured
2026-08-11 on an Apple M-series laptop. The exact string is `REFERENCE_INPUT` in
`tests/test_budgets.py` so a figure can be reproduced rather than argued about.

Stating the length and the thread count is the whole point. The previous version of this
table gave bare millisecond figures with neither, which made every one of them
unfalsifiable: `pii` at "15 ms" is true at 27 tokens and false by a factor of three at the
length the model was trained on. Budgets are per detector, per scan, at that input.

| ID | Side | Tier | Type | Budget (p95) | Measured | Status |
|---|---|---|---|---|---|---|
| `secrets` | input | T0 | regex + entropy | 1 ms | 0.04 ms | built |
| `disclosure` | output | T0 | rule + template match | 5 ms | 0.04 ms | built |
| `pii` | input, output | T1 | NER, XLM-R base ONNX | 75 ms | 51 ms | built |
| `output_leakage` | output | T1 | NER, reuses `pii` weights | 75 ms | 51 ms | built |
| `gibberish` | input | T1 | classifier | 75 ms | – | trained, not wired |
| `injection` | input | T2 | classifier | 75 ms | – | trained, not wired |
| `regulated_advice` | output | T2 | classifier | 75 ms | – | trained, not wired |
| `toxicity` | input, output | T2 | classifier | 75 ms | – | trained, not wired |
| `nsfw` | input, output | T2 | classifier | 75 ms | – | trained, not wired |
| `bias` | output | T2 | classifier | 75 ms | – | trained, not wired |
| `politeness` | output | T2 | classifier | 75 ms | – | trained, not wired |
| `topic_scope` | input | T3 | bi-encoder vs taxonomy | 300 ms | – | needs an export path |
| `groundedness` | output | T3 | evidence scoring vs sources | 300 ms | – | trained, not wired |

Three things this table now says that the old one did not.

**Cost is per token, and linear.** 0.60 ms per token at one thread, measured. Every
model-backed detector is the same XLM-RoBERTa base, so they all cost the same at the same
input length, and the T1/T2 split is about *when* a detector runs and whether a policy may
disable it, not about it being cheaper. A single 75 ms budget for every encoder detector
is the honest consequence.

**The tier ceilings are not per-scan totals.** A full output-side scan with everything
wired would be one rule check plus six encoder passes, roughly 310 ms at the reference
length: `pii` and `output_leakage` share a single pass, and each of the five T2
classifiers is a different model and needs its own. The tier system is what keeps that
off the common path, T2 being disableable and T3 running only on escalation, which is a
scheduling property rather than a cost one.

Measured today, with `disclosure`, `pii` and `output_leakage` wired: 51.9 ms for the
output side. It was 116 ms until `output_leakage` stopped repeating `pii`'s encoder pass
over the same text for the same answer. Sharing the session saved memory; sharing the
inference saved the time.

**Threads buy the old numbers back, and the library will not take them.** Measured at 96
tokens: 54.7 ms at one thread, 29.8 at two, 17.8 at four, 12.4 at eight. So a 15 ms T1
budget is reachable, at the price of taking eight cores from the host application on every
scan. The default stays at one thread, because a library that quietly commandeers the
machine it is embedded in is worse than a library that is honestly slower, and a policy
can raise it deliberately.

`gibberish` is T1 because a gibberish input should short circuit the tiers above it rather
than be scored by them, not because it is cheaper. It is not.

Tier semantics:
- **T0** always runs, cannot be disabled, negligible cost.
- **T1** runs on the standard path.
- **T2** runs on the standard path, may be disabled per policy.
- **T3** runs only when a lower tier flags, or when the policy sets `always: true`.

Latency budgets are asserted in `tests/test_budgets.py`. A change that blows a budget
fails CI. If a budget is genuinely wrong, change the budget in a separate commit with
a measurement in the message, never silently in the same commit as the code.

## Core types

`Decision` and `EvidenceRecord` are the load-bearing structures. Changing them is a
breaking change and needs an explicit instruction.

```
Decision
  verdict: "allow" | "redact" | "block" | "flag"
  text: str                  # possibly redacted or rewritten
  original_text: str
  findings: list[Finding]
  evidence: EvidenceRecord
  elapsed_ms: float
  tiers_run: list[str]

Finding
  detector_id: str
  tier: str
  label: str                 # e.g. "email", "prompt_injection", "financial_advice"
  score: float               # 0.0 to 1.0
  span: tuple[int, int] | None
  action: "block" | "redact" | "rewrite" | "flag" | "log"
  model_id: str | None
  model_revision: str | None

EvidenceRecord
  record_id: str             # UUIDv7
  timestamp: str             # RFC 3339, UTC
  direction: "input" | "output"
  policy_id: str
  policy_hash: str           # sha256 of the resolved policy document
  library_version: str
  detectors: list[DetectorAttestation]   # id, model_id, revision, weights sha256
  input_hash: str            # sha256 of original text, never the text itself
  verdict: str
  finding_summary: list[dict]            # detector_id, label, score, action
  signature: str | None      # Ed25519 over the canonical JSON of the above
```

The evidence record never contains raw user text. It contains hashes. This is not
negotiable and there is a test for it.

Serialisation is canonical JSON (sorted keys, no whitespace) so that hashes and
signatures are reproducible across machines.

## Repo layout

```
src/flowx_border/
  __init__.py          # exports scan_input, scan_output, load_policy only
  types.py             # Decision, Finding, EvidenceRecord, DetectorAttestation
  policy.py            # YAML schema, loader, resolution, hashing
  engine.py            # tier orchestration, short-circuit logic, timing
  evidence.py          # record construction, canonical JSON, signing
  detectors/
    base.py            # Detector protocol
    secrets.py         # T0
    disclosure.py      # T0
    pii.py             # T1
    injection.py       # T2
    regulated_advice.py# T2
    topic_scope.py     # T3
    groundedness.py    # T3
    output_leakage.py  # T1, reuses the pii session, does not load a second copy
  models/
    registry.py        # model id to HF repo and pinned revision
    onnx.py            # ONNX Runtime session management, warm-up, pooling
  adapters/
    langgraph.py
    fastapi.py
    llm_guard_compat.py  # scan_prompt / scan_output shim
tests/
  fixtures/            # golden corpus, one directory per detector
  test_offline.py      # asserts no socket use during scan
  test_budgets.py      # latency assertions
  test_evidence.py     # no raw text in records, reproducible hashes
docs/
policies/
  default.yaml
  bfsi.yaml
```

## What backs each detector

Decided 2026-08-10 after an inventory of the 39 repos on
[huggingface.co/flowxai](https://huggingface.co/flowxai), which is the model
repository for this library. `models/registry.py` pins every entry to a commit sha.

| Detector | Model | State |
|---|---|---|
| `secrets` | – | rules, no weights |
| `disclosure` | – | rules plus a phrasings data file |
| `pii` | `flowxai/piiguard` default, `flowxai/cee-pii` policy-selectable | piiguard has ONNX and INT8 published |
| `output_leakage` | whichever session `pii` loaded | never a second copy |
| `topic_scope` | `flowxai/semantic-mapper` | 4B generative, GGUF only, see the caveat below |
| `injection` | none published | ships unavailable in v1 |
| `regulated_advice` | none published | ships unavailable in v1 |
| `groundedness` | none published | ships unavailable in v1 |

`piiguard` is XLM-RoBERTa base with 7 entity types (CARD, DATE, EMAIL, IBAN,
NATIONAL_ID, PERSON, PHONE) and checksum validation. `cee-pii` is GLiNER with 34
labels weighted toward CEE, and it has no ONNX export yet, so wiring it means doing
that export first. Both are selectable per policy, and `output_leakage` reuses the
session that `pii` already loaded whichever way the policy went.

`piiguard` was trained on **nine** locales, not the two its hub tags advertise: `en`,
`ro`, `bg`, `hu`, `sl`, `hr`, `de`, `it`, `fr`, all of them EU official languages. The
source of truth is `configs/cross/pii_multi.yaml` in the OpenNER training repo, and
the hub tags need fixing to match. Trained at `max_length: 96`, which is the number to
quote when anyone asks what input the latency figures describe.

One thing to know before making per-language claims: in the generator, locale `en` is
labelled United Kingdom but uses the German Steuer-IdNr algorithm as a generic numeric
fallback. A real UK NINo carries no checksum, so a fallback is defensible, but the
model learned a German-shaped number as a UK identifier. Do not state that English
national IDs are checksum validated.

**Three detectors ship unavailable, and they ship loudly.** The registry entry names
the intended repo, the detector raises an error naming the missing model, and the
tests are `xfail` with the repo id in the comment. There is no silent no-op, because
a silent no-op in a security library is a vulnerability. v1 is 5 of 8 detectors real,
stated plainly in the README. Nothing on the site or in the docs may imply otherwise.

**`semantic-mapper` does not fit the detector contract as it stands.** It is a 4B
Qwen3 LoRA that generates JSON against a frozen prompt, published as GGUF. That is a
local LLM call inside a detector, which constraint 4 rules out, and 4B cannot meet a
300 ms CPU budget. `topic_scope` therefore needs either a distilled encoder or an
explicit exception. Raise it before implementing that detector, do not quietly wire
the 4B model in.

Two things to fix on the hub side, not in this repo: no repo carries a `license:` field
in its metadata even where the card states Apache-2.0, and the published `cee-pii` and
`scam-guard-qwen06b` cards still contain pre-publication HTML comments saying "NOT YET
UPLOADED". The registry cannot attest a licence that is not declared.

## Language coverage

Decided 2026-08-10, replacing the earlier five-language target. The supported set is
the 24 official languages of the EU, plus Turkish and Azerbaijani. English is already
an EU official language, so the total is 26, not 25.

| Code | Language | Code | Language | Code | Language |
|---|---|---|---|---|---|
| `bg` | Bulgarian | `et` | Estonian | `lv` | Latvian |
| `hr` | Croatian | `fi` | Finnish | `mt` | Maltese |
| `cs` | Czech | `fr` | French | `pl` | Polish |
| `da` | Danish | `de` | German | `pt` | Portuguese |
| `nl` | Dutch | `el` | Greek | `ro` | Romanian |
| `en` | English | `hu` | Hungarian | `sk` | Slovak |
| `es` | Spanish | `ga` | Irish | `sl` | Slovenian |
| `sv` | Swedish | `it` | Italian | `lt` | Lithuanian |
| `tr` | Turkish (not EU) | `az` | Azerbaijani (not EU) | – | – |

What this obliges:

- Fixtures cover all 26 for every detector. A detector is not done at English plus
  five.
- The `disclosure` phrasings data file carries all 26. That detector is pure data, so
  there is no excuse for a gap.
- Model-backed detectors report per-language evaluation numbers, not one aggregate.
  An aggregate hides the tail, and the tail is the whole point of the project.
- Where a language genuinely underperforms, publish the number and say so. Do not
  drop the language from the table.

Where the models actually are, as of 2026-08-10: `piiguard` covers 9 of the 26 (`en`,
`ro`, `bg`, `hu`, `sl`, `hr`, `de`, `it`, `fr`). The remaining 17 are untested, and the
per-language table says so rather than implying coverage.

Closing that gap is a data task, not a research task, which is the useful thing to know
here. Training data is synthetic and correct by construction, so each new locale needs
a national-ID generator with its real checksum, a phone country code, name lists, and
an email TLD. Most of the 17 have documented schemes: PESEL, Czech and Slovak rodné
číslo, Dutch BSN, Portuguese NIF, Spanish DNI, Swedish personnummer, Finnish
henkilötunnus, Estonian isikukood, Greek AMKA, Irish PPSN, Turkish TC Kimlik.

Two genuine hard cases, and they are different problems:

- **Maltese is not in XLM-RoBERTa's pretraining set.** No amount of synthetic data
  fixes that, it is a base-model decision. Irish, contrary to an earlier note in this
  file, is in XLM-R and should be fine.
- **Maltese and Azerbaijani national IDs have no public checksum scheme**, so those
  two can only be generated format-valid, which makes their labels weaker than the
  rest by construction. Say so on the model card.

## Detector protocol

Every detector implements the same shape. No exceptions, no special cases in
`engine.py` for particular detectors.

```python
class Detector(Protocol):
    id: str
    tier: str
    sides: frozenset[str]  # {"input"}, {"output"}, or both

    def warm(self) -> None: ...
    def run(self, text: str, cfg: DetectorConfig, ctx: Context) -> list[Finding]: ...
```

If a task tempts you to branch on `detector.id` inside the engine, the abstraction is
wrong. Stop and raise it.

## Testing rules

- Tests come first. Write the failing test, then the implementation.
- Every detector needs a golden fixture directory with positive cases, negative cases,
  and coverage of every language in the "Language coverage" section below. English-only
  fixtures are a bug.
- No mocking of the ONNX sessions in detector tests. Test the real model. If that is
  too slow for the default run, mark it `@pytest.mark.slow`, do not fake it.
- `pytest -q` must pass with zero network access.

## Tooling

- Python 3.11+, `uv` for dependency management. The host default interpreter is 3.14,
  so pin the version in `pyproject.toml` and always go through `uv run`, never a bare
  `python` or `pytest`.
- `ruff` for lint and format, `mypy --strict` for types. Both run in CI, both must
  be clean.
- Apache-2.0. Every source file carries the SPDX header.
- Conventional commits.

## Commands

```sh
uv sync                              # install, including dev extras
uv run pytest -q                     # default suite, must pass with no network
uv run pytest -q -m "not slow"       # same thing explicitly, slow marks excluded
uv run pytest -q -m slow             # real models, latency budgets
uv run pytest -q tests/test_evidence.py::test_no_raw_text   # one test
uv run pytest -q tests/fixtures/pii -k romanian             # one detector, one language
uv run ruff check . && uv run ruff format --check .
uv run mypy --strict src
grep -rn "$(printf '\u2014')" --include="*.py" --include="*.md" --include="*.yaml" .   # em-dash check, must find nothing
```

The em-dash check is written with `printf` on purpose. Spelling the character
literally in the pattern would make this file match itself.

Two things to know about running the suite:

- The default run must pass with the network down, and `tests/test_offline.py` enforces
  that by patching `socket.socket` to raise. If a change makes a test need the network,
  the change is wrong, not the test.
- Model-backed detector tests use the real ONNX sessions. When they are too slow for the
  default run, mark them `slow`. Never mock a session to make them fast.

Latency budget work belongs in its own commit, with the measurement in the commit
message. Do not adjust a budget in the same commit as the code that missed it.

## Writing style for all documentation, docstrings, and commit messages

- No em-dashes. Use commas, colons, parentheses, or a full stop.
- En-dashes only for null cells in tables.
- Sentence case for headings.
- No marketing language, no superlatives, no "revolutionary", "seamless", "powerful".
- Claims must be checkable. If a number appears in the README, there must be a
  benchmark in the repo that produces it.

## Compliance language: read this before writing any docs

This library does not make anyone compliant with anything. It produces evidence about
controls that were applied. That distinction is load-bearing and legally material.

Permitted phrasing:
- "produces an auditable record of which checks ran and what they found"
- "detects whether a required disclosure is present in the output"
- "supports the evidence requirements of your own AI governance process"

Forbidden phrasing:
- "AI Act compliant" / "makes your system compliant"
- "guarantees", "ensures", "certified"
- naming a specific regulation as if the library satisfies it

The obligations under the EU AI Act sit with the provider or deployer of the system,
not with a library. Runtime checks can observe a narrow slice of this, mainly whether
a disclosure is present in text and whether the configured controls actually ran.
Say that, and nothing more.

## When to stop and ask

- A new runtime dependency.
- A ninth detector.
- A change to `Decision` or `EvidenceRecord`.
- A third public function.
- Anything that requires network access during a scan.
- A latency budget change.

In all of these, write the proposal into the response and wait. Do not implement and
then explain.
