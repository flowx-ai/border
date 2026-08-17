<!--
Before anything else: please do not paste real personal data, real credentials or real
customer text into this issue.

This is a library for finding exactly those things, so a good bug report naturally wants
to quote the text that went wrong. Send a synthetic equivalent with the same shape
instead: same entity types, same language, same layout. If the shape is what matters, the
shape is what to send, and the tests are full of examples to copy.

An issue on a public repository is permanent and indexed.
-->

## What happened

A sentence or two. If a detector fired when it should not have, or did not fire when it
should, say which one and what label.

## The text, as a synthetic equivalent

```
```

## What you expected, and what you got

Expected:

Got:

## The decision

If you can, paste the findings rather than describing them. This is the most useful thing
in a report about a detector:

```python
for f in decision.findings:
    print(f.detector_id, f.label, round(f.score, 4), f.action, f.span)
```

```
```

## Your setup

Fill in what applies. Most of it comes from one command:

```python
from flowx_border.evidence import library_version
from flowx_border.registry import loaded_detectors, deployment_notes
from flowx_border import load_policy

policy = load_policy("your-policy.yaml")
print("version:", library_version())
print("detectors loaded:", len(loaded_detectors()))
print("notes:", deployment_notes(policy))
```

- **flowx-border version**:
- **Python version**:
- **OS and CPU**:
- **Policy**: one of the shipped ones in `policies/`, or your own with the relevant
  detector block pasted below
- **Weights**: fetched from the hub, or a local `FLOWX_BORDER_MODEL_DIR` override

```yaml
# the relevant part of your policy, if it is your own
```

## Before you file

A few things are known and documented rather than bugs, so a check here may save you the
write-up:

- **A detector reporting that it could not run** is deliberate. `_unconfigured`,
  `_unverifiable` and similar labels mean the check needed something a policy did not
  supply, and it says so instead of passing quietly.
- **Two of the catalogued detectors do not run at all** on a fresh install. See
  [docs/detectors.md](../docs/detectors.md), which is generated from the code and is the
  authority on which.
- **Known false positives** are listed with measurements in
  [docs/reference/performance.md](../docs/reference/performance.md). If the behaviour you
  hit is in there with a number beside it, an issue is still welcome, but say what it cost
  you rather than that it happens.
- **Latency** depends on input length in tokens, and on how many threads the policy
  allows. The default is one thread on purpose. The reference input and the measured
  figures are in the same performance file.

## Asking for something rather than reporting something

That is welcome too, and the two useful things to include are what you would do with it
and what you do today instead. For a new detector, [CONTRIBUTING.md](../CONTRIBUTING.md)
lists the three things one has to satisfy, which is also a fair description of what a
proposal has to argue.
