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

The PII model covers nine of the 26: `en`, `ro`, `bg`, `hu`, `sl`, `hr`, `de`, `it`
and `fr`. The other seventeen are untested rather than unsupported, and closing
that gap is a data task rather than a research one: each locale needs a national
identifier generator with its real checksum, a phone country code, name lists and
an email TLD.

## Where it fails

**Maltese is absent from the base model's pretraining.** No amount of training data
fixes that. It is the weakest language on every classifier and on two of them it
scores zero. It stays in the published table, because a coverage table with the bad
rows removed is not a coverage table.

**Maltese and Azerbaijani national identifiers have no public checksum scheme**, so
those two can only be generated format-valid, which makes their labels weaker than
the rest by construction.

## What not to claim

The English locale in the training generator is labelled United Kingdom but uses a
German identifier algorithm as a generic numeric fallback. A real UK National
Insurance number carries no checksum, so a fallback is defensible, but do not state
that English national identifiers are checksum validated.
