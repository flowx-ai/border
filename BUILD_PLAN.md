# Build plan

Seven phases. Each is a separate Claude Code session. Do not run two phases in one
session, because the context needed for detector work is different from the context
needed for scaffolding and the quality drops.

Each phase has a prompt you can paste directly and a definition of done that you
should check yourself before moving on.

---

## Phase 0: skeleton and contracts

Nothing runs yet. This phase exists so that every later phase has a fixed target.

**Prompt**

```
Read CLAUDE.md fully before doing anything.

Set up the repository skeleton exactly as described in the "Repo layout" section.
Implement only:

1. src/flowx_border/types.py with Decision, Finding, EvidenceRecord and
   DetectorAttestation as Pydantic v2 models, matching the "Core types" section
   field for field. Add a canonical_json() helper that produces sorted-key,
   whitespace-free JSON bytes.
2. src/flowx_border/detectors/base.py with the Detector Protocol and DetectorConfig
   and Context types.
3. src/flowx_border/__init__.py exporting scan_input, scan_output, load_policy as
   stubs that raise NotImplementedError.
4. pyproject.toml with uv, ruff, mypy strict, pytest, Apache-2.0, Python 3.11+.
5. CI workflow running ruff, mypy --strict, and pytest with no network.
6. tests/test_types.py covering canonical JSON reproducibility and the assertion
   that EvidenceRecord has no field capable of holding raw text.

Do not implement the engine, the policy loader, or any detector. Do not add
dependencies beyond pydantic and pyyaml.

Write the tests first.
```

**Definition of done**
- `uv run pytest -q` passes.
- `uv run mypy --strict src` is clean.
- `EvidenceRecord` cannot hold raw text and there is a test proving it.
- Two consecutive `canonical_json()` calls on equivalent objects produce identical bytes.

---

## Phase 1: policy and engine

Still no detectors. The engine orchestrates an empty set, which is the right time to
get the tier logic right.

**Prompt**

```
Read CLAUDE.md.

Implement the policy layer and the engine.

policy.py:
- Pydantic schema for the YAML policy. Top level: policy_id, version, description,
  fail_mode (open|closed) per tier, and a detectors mapping.
- Each detector entry: enabled, threshold, on_fail (block|redact|rewrite|flag|log),
  and an optional always flag for T3.
- load_policy(path) resolves defaults, validates, and computes policy_hash as the
  sha256 of the canonical JSON of the resolved document.
- Unknown detector ids in a policy file are an error, not a warning.

engine.py:
- run_scan(text, side, policy, ctx, detectors) implementing tier order T0, T1, T2,
  then T3 only if a lower tier produced a finding above threshold or the T3 detector
  is marked always.
- Short-circuit: if any finding has action "block", stop and do not run later tiers.
- Per-tier timing recorded into Decision.elapsed_ms and tiers_run.
- fail_mode handling: on a detector exception, fail_closed means verdict "block",
  fail_open means log the exception as a finding with action "log" and continue.
- Redaction: apply spans right to left so offsets stay valid.

Wire scan_input and scan_output to run_scan with the correct side.

Write policies/default.yaml and policies/bfsi.yaml. bfsi.yaml sets fail_mode closed
for T0 and T1, enables all eight detectors, and sets regulated_advice to block.

Tests: tier ordering, short-circuit, fail_open vs fail_closed, redaction offset
correctness with overlapping spans, policy_hash stability across whitespace and key
order changes in the YAML source.

Use fake in-memory detectors in the tests. Do not implement any real detector.
```

**Definition of done**
- Tier order and short-circuit are covered by tests, including the overlapping span case.
- Reordering keys or reformatting a policy YAML does not change `policy_hash`.
- A detector that raises produces a sane `Decision` under both fail modes.

---

## Phase 2: T0 detectors and evidence signing

First real output. After this phase the library does something useful with zero model
downloads, which matters for the first-run experience.

**Prompt**

```
Read CLAUDE.md.

Implement the two T0 detectors and the evidence layer.

detectors/secrets.py:
- Regex set for common credential shapes: AWS keys, GitHub tokens, Slack tokens,
  private key headers, JWT, generic high-entropy strings above a configurable
  Shannon entropy threshold with a minimum length.
- Findings carry label, span, and score. Score is 1.0 for a pattern match and the
  normalised entropy for the entropy rule.

detectors/disclosure.py:
- Checks whether the output contains a disclosure that it was AI generated.
- Configurable: a list of accepted phrasings per language, loaded from a YAML data
  file, not hardcoded in Python.
- Ships with phrasings for English, Romanian, Polish, Hungarian, Turkish, Azerbaijani.
- Finding label "disclosure_missing" when none matched.

evidence.py:
- build_record(...) assembling EvidenceRecord from the scan.
- Optional Ed25519 signing over canonical_json, using cryptography. Key is supplied
  by the caller, never generated or stored by the library.
- verify_record(record, public_key) helper.

Tests: golden fixtures for both detectors with positive, negative, and the six
languages. Round-trip signing and verification. A test asserting no raw text appears
anywhere in a serialised record for an input containing a distinctive marker string.
```

**Definition of done**
- `scan_output` on a plain answer with no disclosure returns a `disclosure_missing` finding.
- A distinctive marker in the input text never appears in the serialised evidence record.
- Sign then verify round-trips, and mutating one byte of the record fails verification.

---

## Phase 3: model runtime and the PII detector

The first model. Get the loading and caching story right here, because the next three
detectors inherit it.

**Prompt**

```
Read CLAUDE.md.

Implement the model runtime and the T1 PII detector.

models/registry.py:
- Map model_id to a Hugging Face repo and a PINNED revision (commit sha, never a
  branch name). Include the weights sha256 for attestation.
- resolve(model_id) returns a local path, downloading via huggingface-hub if absent.
- Honour HF_HUB_OFFLINE. If a model is missing and offline is set, raise a clear
  error naming the model and the expected cache path.

models/onnx.py:
- Lazy ONNX Runtime session creation, one session per model id, thread-safe.
- Warm-up pass on first load so the first real scan is not the slow one.
- Explicit intra_op thread count, configurable, defaulting to 1 so the library does
  not fight the host application for cores.

detectors/pii.py:
- GLiNER-class NER over ONNX. Entity types configurable via policy.
- Long inputs handled by windowing with overlap, spans mapped back to original offsets.
- Findings carry entity label, span, and model confidence.
- Redaction replaces the span with a typed placeholder, for example [EMAIL].

detectors/output_leakage.py reuses the same loaded session, it does not load a
second copy.

Tests: real model, no mocks. Offset correctness across window boundaries. Fixtures in
all six languages. A test asserting the second scan is faster than the first, proving
warm-up and session reuse.
```

**Definition of done**
- Two detectors share one loaded session and there is a test proving it.
- Entity spans are correct across a window boundary.
- `HF_HUB_OFFLINE=1` with a cold cache produces a readable error, not a stack trace.
- p95 under the 15 ms budget on your reference machine, recorded in the commit message.

---

## Phase 4: T2 classifiers

**Prompt**

```
Read CLAUDE.md.

Implement the two T2 classifier detectors on top of the existing ONNX runtime.

detectors/injection.py:
- Binary or multi-label classifier over the input text: direct injection, indirect
  injection, jailbreak attempt, benign.
- Threshold from policy. Score is the model probability.

detectors/regulated_advice.py:
- Multi-label over the output text: financial advice, medical advice, legal advice,
  none. This is the detector with no open-source equivalent, so the fixture corpus
  matters more than usual.
- Fixtures must include the hard negatives: general explanation of a concept versus
  a personalised recommendation. Explaining what an ETF is should be "none".
  Telling the user which ETF to buy should fire.

Both detectors chunk long text and take the maximum score across chunks.

If a model does not exist yet in the registry, add the entry pointing at the intended
repo id and write the detector against it, then mark the tests xfail with a comment
naming the missing model. Do not substitute a different model silently.
```

**Definition of done**
- The hard-negative fixtures for `regulated_advice` pass, specifically the
  explanation versus recommendation distinction.
- Chunking with max-pooling is tested on text longer than the model context.
- Any missing model is xfail with the repo id named, not quietly stubbed.

---

## Phase 5: T3 detectors

**Prompt**

```
Read CLAUDE.md.

Implement the two T3 detectors. These run rarely, so favour correctness and
explainability over speed.

detectors/topic_scope.py:
- Takes a taxonomy of allowed and disallowed topics from the policy file.
- Uses the semantic mapper model to score the input against each taxonomy node.
- Finding carries the matched node path so the operator can see why it fired.

detectors/groundedness.py:
- Takes source passages from Context. If Context has no sources, the detector is a
  no-op and records that fact rather than passing silently.
- Scores each output sentence against the sources and returns per-sentence findings
  for unsupported claims, with the span of the offending sentence.

Both must record in the Finding why they ran: which lower-tier finding triggered
escalation, or that policy set always: true.
```

**Definition of done**
- A T3 detector with no inputs available records a no-op, it does not silently pass.
- Findings name the escalation reason.
- Taxonomy node paths appear in findings.

---

## Phase 6: adapters and migration shim

This is the distribution phase. The library is only as adopted as its cheapest
integration path.

**Prompt**

```
Read CLAUDE.md.

Implement the three adapters. Each is thin. If an adapter needs more than about 120
lines, the core API is wrong and you should say so instead of writing around it.

adapters/langgraph.py:
- A node factory: guard_node(policy, side) returning a callable suitable for a
  LangGraph graph, reading and writing the message state.
- On a block verdict, route to a configurable terminal node rather than raising.

adapters/fastapi.py:
- Middleware plus a dependency, both offered. The middleware form intercepts a
  configurable request and response JSON path.

adapters/llm_guard_compat.py:
- scan_prompt(prompt, scanners) and scan_output(prompt, output, scanners) matching
  the archived llm-guard signatures, returning its tuple shape.
- Maps its scanner names onto our detector ids where a real equivalent exists.
- For a scanner with no equivalent, raise a clear NotImplementedError naming it.
  Do not silently no-op, because a silent no-op in a security shim is worse than
  an error.
- docs/migrating-from-llm-guard.md with the full mapping table, including the
  unsupported list.

Each adapter needs an integration test that runs a real scan through it.
```

**Definition of done**
- No adapter exceeds roughly 120 lines.
- Unsupported compat scanners raise, they do not no-op.
- The migration doc names every scanner, supported or not.

---

## Phase 7: benchmarks and README

Do this last, and treat every number in the README as something you have to defend.

**Prompt**

```
Read CLAUDE.md, especially the writing style and compliance language sections.

1. bench/ with a reproducible latency benchmark per detector and per tier
   combination, reporting p50 and p95 on CPU, emitting JSON and a markdown table.
   Record the machine spec in the output.
2. tests/test_budgets.py asserting the p95 budgets from CLAUDE.md, marked slow.
3. tests/test_offline.py asserting no socket is opened during a scan, by patching
   socket.socket to raise.
4. README.md. Structure: what it is, what it is not, install, the two functions,
   the policy file, the evidence record, the benchmark table, the detector table,
   limitations.

The "what it is not" section is mandatory and comes early. It should say plainly:
not a gateway, not a proxy, does not make anyone compliant with any regulation,
does not replace a security review.

Every number in the README must come from bench/ output. If you cannot produce a
number from the repo, do not put it in the README.
```

**Definition of done**
- Every README number traces to a benchmark you can rerun.
- The "what it is not" section is above the fold.
- No em-dashes anywhere in the repo, verified by a grep in CI.

---

## Things worth intervening on

Claude Code will drift on these specifically. Watch for them.

**Detector creep.** It will want a ninth and tenth detector, usually toxicity and
sentiment. Both are commodity, both are what made the predecessor projects wide and
shallow. Hold at eight until v1 ships.

**Framework wrapping.** It will suggest a `Guard` class that wraps your LLM call,
because that is what the training data shows for this problem shape. The two-function
API is the differentiator. Push back.

**Compliance overclaim.** Documentation drafts will reach for "ensures compliance with
the EU AI Act". The CLAUDE.md section covers this, but check every doc commit anyway,
because this is the failure that costs credibility with the exact buyer you want.

**Silent fallbacks.** Missing model, unsupported scanner, no sources for groundedness.
The instinct is to degrade gracefully. In a security library a silent degradation is a
vulnerability. Every one of these should be loud.

**English-only fixtures.** It will write good English test cases and stop. The
multilingual coverage is the moat, so it has to be in the fixtures from Phase 2
onward, not retrofitted.

---

## Suggested session hygiene

- One phase per session, `/clear` between phases.
- Start every session with "read CLAUDE.md fully before doing anything", because the
  auto-load does not guarantee it actually attends to the constraints.
- After each phase, run the definition of done yourself rather than accepting the
  summary. The failure mode is a passing test suite that tests the wrong thing.
- Commit at the end of each phase, tagged `phase-N`, so a bad phase is one revert.
