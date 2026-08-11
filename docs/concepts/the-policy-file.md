---
title: The policy file
description: How a policy is written, how it resolves, and why it is data rather than code.
group: Concepts
order: 2
---

# The policy file

A policy is a YAML document validated by a schema. It has no expressions and no
callbacks. A compliance officer who does not write Python must be able to read one
and say whether it is right, and that is only true if there is nothing executable
in it.

```yaml
policy_id: default
version: 1
description: What this policy is for.

fail_mode: open

detectors:
  pii:
    enabled: true
    on_fail: redact
    threshold: 0.5
    options:
      entities: [EMAIL, IBAN, PERSON]
```

## Resolution

`load_policy` does more than parse. It validates, fills defaults, and produces a
*resolved* document in which every known detector appears explicitly and
`fail_mode` is expanded to one entry per tier. The hash in the evidence record is
taken over that resolved document.

This matters more than it looks. Two deployments that write different shorthand but
mean the same thing produce the same hash, and two that mean different things
produce different hashes even if the files look similar.

`load_policy` never falls back to a default. An unknown detector id, a threshold
outside 0 to 1, or an unexpected key is an error, because scanning under a policy
the caller did not write is worse than refusing to start.

## fail_mode

What happens when a detector cannot run.

```yaml
fail_mode: open          # applies to every tier

fail_mode:               # or per tier
  T0: closed
  T1: closed
  T2: open
  T3: open
```

`open` records the breakage as a finding and continues. `closed` treats an
unavailable check as a failed check.

`open` is the right default for a first install, because a library that starts
blocking traffic the day a model fails to load gets removed rather than fixed. In a
regulated context the cheap tiers are usually `closed`, because "we could not tell"
is not an answer you can put in front of a supervisor. Failing closed on a 300 ms
model that did not load would take the whole assistant down, which is why the
shipped `bfsi` policy closes T0 and T1 and leaves T2 and T3 open.

## Per detector

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Off means the detector does not run. T0 cannot be disabled. |
| `on_fail` | `flag` | `block`, `redact`, `rewrite`, `flag` or `log`. |
| `threshold` | `0.5` | 0 to 1. Below this, a score is not a finding. |
| `always` | `false` | T3 only: run every time rather than on escalation. |
| `options` | `{}` | Detector-specific settings, such as PII entity types. |

Unknown keys are rejected rather than ignored. A typo in a policy file should stop
the process, not silently disable a check.

## On thresholds

A threshold left at a plausible-looking default is how a detector becomes a no-op
that still produces evidence records. Four of the shipped classifiers reported an
F1 of 0.000 at 0.5 in all 26 languages, because their scores separate positives
from negatives well below it. The shipped policies carry calibrated values, and a
detector whose threshold is not listed there has not been calibrated yet. Treat
that as unmeasured rather than as correct.
