---
title: The evidence record
description: What a record contains, what it never contains, and how to verify one.
group: Concepts
order: 4
---

# The evidence record

Every scan produces one. It is the artifact that makes a decision reviewable six
months later by somebody who was not there.

```json
{"detectors":[{"id":"secrets"},
   {"id":"pii","model_id":"piiguard","revision":"018e7f0355c0",
    "weights_sha256":"3b1f..."}],
 "direction":"input",
 "finding_summary":[{"detector_id":"pii","label":"iban",
   "score":0.98,"action":"redact"}],
 "input_hash":"9f2b...","policy_hash":"4c81...",
 "verdict":"redact"}
```

## It never contains the text

It contains hashes. This is not negotiable and there is a test for it.

The cost of that choice is real: you cannot reconstruct what was said from a
record. You can only prove that a given text was the one checked. The benefit is
that the record can be archived in a system scoped for audit logs rather than one
scoped for customer data, and it does not become a second copy of the thing you
redacted.

## What it ties together

- `record_id`, a UUIDv7, and an RFC 3339 timestamp in UTC.
- `direction`, so a record is unambiguous about which side it describes.
- `policy_id` and `policy_hash`, over the *resolved* document.
- `library_version`.
- `detectors`, one attestation each: id, model id, revision, and the sha256 of the
  weights that ran.
- `input_hash`.
- `verdict` and a `finding_summary` of detector, label, score and action.
- `signature`, optionally.

The model revision is the field that does the long-term work. It is what lets
somebody asking "how well did this work in Hungarian" resolve a decision to the
evaluation table published for exactly those weights.

## Determinism

Serialisation is canonical JSON: sorted keys, no whitespace. Given the same inputs
and the same model revisions, a scan produces the same record on another machine.
There is no sampling, no temperature and no time-dependent behaviour inside a scan.

## Signing

Signing is optional and the library never holds a key. `sign_record` takes one you
own and produces an Ed25519 signature over the canonical JSON of everything above.
Most callers archive records without signing them, which is why `cryptography` is
an optional extra rather than a dependency.
