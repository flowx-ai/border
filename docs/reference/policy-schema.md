---
title: Policy schema
description: Every key a policy document accepts, with its default and its constraint.
group: Reference
order: 2
---

# Policy schema

Unknown keys are rejected at every level. A typo should stop the process rather
than silently disable a check.

## Document

| Key | Type | Required | Constraint |
|---|---|---|---|
| `policy_id` | `str` | yes | `^[a-z0-9][a-z0-9._-]{0,63}$` |
| `version` | `int` | yes | at least 1 |
| `description` | `str` | no | defaults to empty |
| `fail_mode` | `str` or mapping | yes | `open` or `closed`, per tier or for all |
| `detectors` | mapping | yes | detector id to settings |

## Detector

| Key | Type | Default | Constraint |
|---|---|---|---|
| `enabled` | `bool` | `true` | T0 cannot be disabled |
| `on_fail` | `str` | `flag` | one of `block`, `redact`, `rewrite`, `flag`, `log` |
| `threshold` | `float` | `0.5` | 0.0 to 1.0 inclusive |
| `always` | `bool` | `false` | T3 only |
| `options` | mapping | `{}` | detector specific |

## Errors

`load_policy` raises `PolicyError` for anything wrong with the document, including
an unknown detector id. `DetectorUnavailableError` is a subclass of it, raised when
a policy expects a detector this install does not have in order to enforce
something.

Both are raised rather than warned. Scanning under a policy the caller did not
write is worse than refusing to start.
