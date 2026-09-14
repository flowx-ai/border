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

## Selecting a model

A detector's `options` can name which model backs it, where more than one exists.
`pii` has two: `piiguard`, the default, and `flowxai/cee-pii`, selected by name.

```yaml
detectors:
  pii:
    enabled: true
    on_fail: redact
    threshold: 0.5
    options:
      model: cee-pii
      entities: [person, email, phone]
```

Two models do not have to tag the same things, and since 2026-09-14 these two do
not: cee-pii tags `organisation`, a company or employer name, and piiguard has no head
for it. So `entities`, `entity_actions` and `entity_thresholds` are checked against the
model the policy selected, not against a union of both. Naming a type the selected model
cannot tag raises, and names the types it can:

    pii: unknown entity type(s) organisation. This model tags card, date, email,
    iban, location, national_id, person, phone.

That refusal is the point of validating per model. The alternative, accepting every name
either model knows, would let a policy ask piiguard for company names and report success
on every text, which reads exactly like a document that contains none.

Selecting a model is a deployment decision, not just a policy one, and the two
consequences are different. If the model is unavailable, `load_policy` refuses a
policy that would enforce with it (`on_fail` other than `flag` or `log`) before any
text is scanned, the same way it refuses a policy naming an unknown detector.
`registry.deployment_notes(policy)` separately reports what the selection asks of
the deployment, such as a GPU, so a caller finds out at load time rather than from a
latency graph in production.

## A detector that cannot run on the side you scan

Every detector declares which directions it applies to, and the engine honours that: an
output-side detector is not a candidate during `scan_input`. That is correct, and it is
also easy to configure straight past. A deployment enabled `regulated_advice` at
`on_fail: block`, scanned user questions through `scan_input`, saw no finding on ten
plainly-worded investment-advice questions, and reasonably concluded the model did not
cover the category. The detector had never run. `regulated_advice` looks at whether an
answer *gives* regulated advice, and a question asking for it is on the other side.

`registry.side_notes(policy, side)` returns one line per enabled detector that cannot
run on that direction:

    regulated_advice runs on output only, so it contributes nothing to an input
    scan. It is set to block, so a caller scanning only this direction has
    configured an enforcing check that cannot fire.

It returns lines rather than raising, for `deployment_notes`' reasons and one more. Most
callers scan both directions, so an output-side detector contributing nothing to
`scan_input` is the normal case and not an error. Only the caller knows whether they
ever call the other function, so only the caller can decide whether a line here is a
note or a hole. If you scan one direction only, treat a non-empty result mentioning an
enforcing action as fatal.

## Describing a taxonomy: say what a node is, never what it is not

`topic_scope` takes its taxonomy from the policy rather than from weights, so the wording
of a node is a configuration decision with a measurable effect. One rule governs it: a
bi-encoder compares meanings and has no representation for negation.

A disallowed node reading `companies other than this one` does not embed as an exclusion.
It embeds roughly as "confidential details of companies", which is near every question
anyone asks in a data room, so the node matches the traffic it was written to let through.

    # reads as the thing it was meant to exclude
    disallowed:
      - path: other_companies
        description: companies other than this one

    # reads as itself
    disallowed:
      - path: competitor_financials
        description: competitor revenue, margins and customer lists

**This fails in the direction that looks safe**, which is why it is worth stating here
rather than leaving to a docstring. An over-broad disallowed node refuses real work
rather than admitting bad work, so it presents as a strict boundary rather than a broken
one, and the only symptom is a refusal rate nobody has a baseline for.

A deployment reported the effect on 2026-09-14 against their own taxonomy and their own
720 ordinary questions: three of their four disallowed nodes were phrased by exclusion,
and rewriting them positively took refusals from 132 to 96. That is their measurement on
their data, not a benchmark in this repository, and the mechanism is what generalises
rather than the figure.

Two related things when writing one:

- **Sweep the threshold on your own taxonomy.** More nodes mean more chances of a
  spurious near-match, so the bar moves with the taxonomy. `policies/default.yaml`
  carries the sweep behind the shipped 0.85 and the reason a previous 0.45 could reject
  nothing at all.
- **The runner-up is available.** The detector emits `nearest__<path>` at `action: log`
  carrying the closest allowed node and its score, so the margin between the winning node
  and the best allowed one is computable per scan without changing anything.

## On thresholds

A threshold left at a plausible-looking default is how a detector becomes a no-op
that still produces evidence records. Four of the shipped classifiers reported an
F1 of 0.000 at 0.5 in all 26 languages, because their scores separate positives
from negatives well below it. The shipped policies carry calibrated values, and a
detector whose threshold is not listed there has not been calibrated yet. Treat
that as unmeasured rather than as correct.

### An omitted threshold is not an inherited one

**Omitting `threshold` gives you 0.5, not the value the detector ships at.**
`DetectorPolicy.threshold` defaults to a flat 0.5 for every detector in the
catalogue, and `load_policy` fills it in before anything else sees the document. So
a policy that says nothing about a threshold has not deferred the decision, it has
made one.

For eight of the ten model-backed detectors that is nowhere near the shipped value:

| detector | `policies/default.yaml` | what an omission gives you |
|---|---|---|
| `gibberish` | 0.37 | 0.5, less sensitive |
| `injection` | 0.43 | 0.5, less sensitive |
| `nsfw` | 0.76 | 0.5, more sensitive |
| `bias` | 0.77 | 0.5, more sensitive |
| `moderation` | 0.80 | 0.5, more sensitive |
| `toxicity` | 0.81 | 0.5, more sensitive |
| `topic_scope` | 0.85 | 0.5, more sensitive |
| `politeness` | 0.89 | 0.5, more sensitive |

The reason this is easy to miss twice over: the package ships `src/flowx_border`
and not `policies/`, so an installed copy of the library does not contain the file
those numbers live in. `flowx_border.detectors.catalogue.CATALOGUE[id].shipped_threshold`
carries them, and `tests/test_thresholds_shipped.py` pins that table against the
policy file in both directions.

It fails quietly in both directions, and they are not equally bad. Below the shipped
bar the detector over-fires, which is visible: a caller sees refusals and
investigates. Above it the detector under-fires, which produces no finding, no
evidence record and nothing to notice, and that is the direction an omission takes
`injection` and `gibberish`.

`registry.threshold_notes(policy)` names every enabled detector whose resolved
threshold differs from the shipped one, and says the configured action, so a lowered
bar on a blocking detector reads differently from one on a `log`:

```python
from flowx_border import load_policy
from flowx_border.registry import threshold_notes

for line in threshold_notes(load_policy("policy.yaml")):
    print(line)
```

It reports rather than corrects, for the reason `deployment_notes` does: a policy
above the shipped bar may be a deliberate profile, and only the caller knows.
`policies/bfsi.yaml` produces nine such lines on purpose. It produced a tenth that
was not on purpose, and that is why this section exists: that file enables
`politeness`, stated no threshold for it, and had been running it at 0.5 against
0.89 since it was written.
