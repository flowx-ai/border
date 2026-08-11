---
title: Types
description: Decision, Finding, EvidenceRecord and the literals they use.
group: Reference
order: 1
---

# Types

Changing `Decision` or `EvidenceRecord` is a breaking change.

## Decision

| Field | Type | Notes |
|---|---|---|
| `verdict` | `Verdict` | The strongest action any finding produced. |
| `text` | `str` | Possibly redacted or rewritten. Use this going forward. |
| `original_text` | `str` | What you passed in. |
| `findings` | `list[Finding]` | Empty when nothing fired. |
| `evidence` | `EvidenceRecord` | Always present, including on `allow`. |
| `elapsed_ms` | `float` | Wall clock for the scan. |
| `tiers_run` | `list[str]` | Which tiers actually executed. |

## Finding

| Field | Type | Notes |
|---|---|---|
| `detector_id` | `str` | |
| `tier` | `str` | |
| `label` | `str` | For example `email`, `prompt_injection`. |
| `score` | `float` | 0.0 to 1.0. |
| `span` | `tuple[int, int] \| None` | Character offsets into `original_text`. |
| `action` | `Action` | What the policy said to do. |
| `model_id` | `str \| None` | `None` for rule detectors. |
| `model_revision` | `str \| None` | |

## EvidenceRecord

| Field | Type | Notes |
|---|---|---|
| `record_id` | `str` | UUIDv7. |
| `timestamp` | `str` | RFC 3339, UTC. |
| `direction` | `"input" \| "output"` | |
| `policy_id` | `str` | |
| `policy_hash` | `str` | sha256 of the resolved policy. |
| `library_version` | `str` | |
| `detectors` | `list[DetectorAttestation]` | id, model id, revision, weights sha256. |
| `input_hash` | `str` | sha256 of the original text. |
| `verdict` | `str` | |
| `finding_summary` | `list[dict]` | detector_id, label, score, action. |
| `signature` | `str \| None` | Ed25519 over the canonical JSON. |

The record is frozen and its collections are tuples. A mutable list inside an audit
artifact is not immutable in any useful sense.

## Literals

```python
Verdict   = "allow" | "redact" | "block" | "flag"
Action    = "block" | "redact" | "rewrite" | "flag" | "log"
Tier      = "T0" | "T1" | "T2" | "T3"
Direction = "input" | "output"
```
