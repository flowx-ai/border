---
title: Quickstart
description: Install it, write a policy, scan a turn in both directions, and read the record.
group: Getting started
order: 2
---

# Quickstart

## Install

```
pip install flowx-border
```

Python 3.11 or newer. Model weights are fetched once on first load and cached.
After that a scan needs no network.

## Write a policy

Policy is data, not code. There is no Python callback in it, which is the
constraint that lets someone who does not write Python review what your system
checks.

```yaml
policy_id: default
version: 1
description: >
  Balanced starting point. Secrets are blocked, personal data is redacted rather
  than blocked, and the expensive checks run only on escalation.

fail_mode: open

detectors:
  secrets:
    on_fail: block
  pii:
    on_fail: redact
    threshold: 0.5
    options:
      entities: [CARD, DATE, EMAIL, IBAN, NATIONAL_ID, PERSON, PHONE]
      entity_actions:
        date: flag            # found and recorded, but left in the text
  disclosure:
    on_fail: flag
```

`entity_actions` overrides `on_fail` for one entity type. The shipped default uses it for
dates, because a bare date is not personal data: a date of birth beside a name is, a
delivery date is not, and the detector cannot tell them apart. Measured over 234 ordinary
sentences in 26 languages, redacting every date removed text from 59 percent of them,
including clock times and a temperature reading.

It is an override rather than a shorter `entities` list on purpose. Dropping `DATE` from
the list would stop the detector reporting dates at all, and an evidence record for a
text full of dates would then look exactly like one for a text with none. Set it back to
`redact` where dates are sensitive; `policies/bfsi.yaml` does.

## Scan a turn

```python
from flowx_border import scan_input, scan_output, load_policy

policy = load_policy("border-code.yaml")

crossing = scan_input(user_text, policy)
if crossing.verdict == "block":
    return refuse(crossing.evidence.record_id)

answer = your_model.complete(crossing.text)

out = scan_output(answer, policy)
archive(out.evidence)
return out.text
```

Use `crossing.text` going forward, not the text you passed in. When a detector
redacts, that is where the redacted version is.

## Read what came back

```python
print(crossing.verdict)        # allow | redact | block | flag
print(crossing.elapsed_ms)
print(crossing.tiers_run)      # ["T0", "T1"]

for finding in crossing.findings:
    print(finding.detector_id, finding.label, finding.score, finding.action)
```

## Archive the record

```python
record = crossing.evidence

record.record_id       # UUIDv7
record.timestamp       # RFC 3339, UTC
record.policy_hash     # sha256 of the resolved policy document
record.input_hash      # sha256 of the original text, never the text
record.verdict
record.detectors       # one attestation per detector that ran
```

Serialise it as canonical JSON, sorted keys and no whitespace, so the hash and any
signature reproduce on another machine.
