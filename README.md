# flowx-border

Inspects the text going into and coming out of an LLM, and returns a structured decision
plus an evidence record. It ships its own open-weight detection models and runs them on
CPU.

Two functions. It does not sit in front of your model, hold your API key, or make the
call for you.

## Install

```sh
pip install flowx-border
```

Python 3.11 or newer. Two optional extras exist because two detectors need a parser:
`flowx-border[sql]` for `sql_injection` and `flowx-border[schema]` for `json_schema`.

Model weights are fetched once, on first load, and cached. After that a scan needs no
network.

## Use

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

Both functions take `(text, policy, ctx=None)` and return a `Decision`:

```
verdict         "allow" | "redact" | "block" | "flag"
text            possibly redacted or rewritten
original_text   what came in
findings        one Finding per detection: detector, label, score, span, action
evidence        EvidenceRecord
elapsed_ms      float
tiers_run       which tiers ran, which is not always all of them
```

`ctx` carries what the text does not say: `sources` for groundedness, an optional
`locale` hint, and free metadata. A detector that needs it and does not get it reports
that it could not run rather than passing quietly.

## Policy

Policy is data, never code. Two policies ship in `policies/`.

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
    on_fail: block
  pii:
    on_fail: redact
    threshold: 0.5
    options:
      entities: [CARD, DATE, EMAIL, IBAN, NATIONAL_ID, PERSON, PHONE]
      entity_actions:
        date: flag    # found and recorded, but left in the text
  toxicity:
    on_fail: flag
```

Detectors run in tiers. T0 always runs and cannot be disabled. T1 and T2 run on the
standard path, and T2 may be disabled per policy. T3 runs only when a lower tier flags,
or when the policy sets `always: true`.

`registry.deployment_notes(policy)` returns one line per thing a policy asks of the
machine beyond a CPU and the base install.

## Evidence

Every scan produces a record. It contains hashes, never raw user text.

```python
from flowx_border.evidence import sign_record, verify_record

signed = sign_record(decision.evidence, your_private_key)
assert verify_record(signed, your_public_key)
```

The library never holds a signing key. Serialisation is canonical JSON, so a hash
computed on one machine matches one computed on another, and a scan is deterministic
given the same input and the same model revisions.

**This does not make anyone compliant with anything.** It records which checks ran and
what they found. Obligations under any AI regulation sit with the provider or deployer of
a system, not with a library inside it.

## Documentation

| | |
|---|---|
| [Quickstart](docs/getting-started/quickstart.md) | a first scan, and the policy file |
| [The two functions](docs/concepts/the-two-functions.md) | what a `Decision` means |
| [The evidence record](docs/concepts/the-evidence-record.md) | fields, hashing, signing |
| [Tiers](docs/concepts/tiers.md) | what runs when |
| [Offline](docs/concepts/offline.md) | what works with the network down |
| [Detectors](docs/detectors.md) | every detector, generated from the code |
| [Measured performance](docs/reference/performance.md) | latency and quality, per detector |
| [Languages](docs/reference/languages.md) | the 26 supported languages |
| [Migrating from llm-guard](docs/migrating-from-llm-guard.md) | scanner to detector mapping |

Not every catalogued detector runs on a fresh install. `docs/detectors.md` is generated
from the code and says which, and the numbers in `docs/reference/performance.md` come
from `benchmarks/collect.py`.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) has the setup, the test markers and what a change has
to satisfy. Please do not put real personal data in an issue: this library exists to find
it, so send a synthetic equivalent with the same shape.

## Licence

Apache-2.0.
