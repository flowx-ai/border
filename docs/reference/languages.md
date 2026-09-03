---
title: Language coverage
description: The 26 target languages, what is actually covered, and where it fails.
group: Reference
order: 4
---

# Language coverage

The supported set is the 24 official languages of the European Union plus Turkish
and Azerbaijani. English is already an EU official language, so the total is 26.

| | | | | | |
|---|---|---|---|---|---|
| `bg` Bulgarian | `hr` Croatian | `cs` Czech | `da` Danish | `nl` Dutch | `en` English |
| `et` Estonian | `fi` Finnish | `fr` French | `de` German | `el` Greek | `hu` Hungarian |
| `ga` Irish | `it` Italian | `lv` Latvian | `lt` Lithuanian | `mt` Maltese | `pl` Polish |
| `pt` Portuguese | `ro` Romanian | `sk` Slovak | `sl` Slovenian | `es` Spanish | `sv` Swedish |
| `tr` Turkish | `az` Azerbaijani | | | | |

## What is measured

Every classifier is scored separately in all 26, at its calibrated threshold, on
corpora generated per language rather than translated. There is no aggregate
number, because an aggregate hides the tail and the tail is the point.

`pii`'s default model, `piiguard`, is trained on all 26: read the current set off
`registry.MODELS["piiguard"].trained_languages` rather than off this file, since it
moves when the pinned weights do.

`pii`'s second, policy-selectable model does not carry that claim. Setting
`pii: { options: { model: cee-pii } }` in a policy switches to `flowxai/cee-pii`, a
GLiNER model trained on Romanian, Polish, Hungarian, Uzbek and both English
variants. Four of those, `en`, `ro`, `pl` and `hu`, are in the 26; Uzbek is not a
language this library claims at all. No per-language evaluation exists for cee-pii
yet, so it has no row in the tables below: `docs/reference/performance.md` reports
its latency and says `quality: not recorded` rather than a score. Selecting it also
means the deployment needs a GPU, which `registry.deployment_notes(policy)` reports
the moment a policy switches it on.

## Where it fails

**Maltese is absent from the base model's pretraining, and that is a fact about the
base model, not a working explanation for a weak score by itself.** This file said
Maltese scored zero on two classifiers and that no amount of data would fix it,
which was true of the corpus that existed at the time: those scores rested on two
positive examples per language, and grew to ten. `docs/reference/performance.json`
is the current, regenerated reading, and Maltese is not near zero on any classifier
in it today. Before attributing a weak score to the pretraining gap, check the
sample size it rests on.

**Maltese and Azerbaijani national identifiers have no public checksum scheme**, so
those two can only be generated format-valid, which makes their labels weaker than
the rest by construction.

## What not to claim

The English locale in the training generator is labelled United Kingdom but uses a
German identifier algorithm as a generic numeric fallback. A real UK National
Insurance number carries no checksum, so a fallback is defensible, but do not state
that English national identifiers are checksum validated.
