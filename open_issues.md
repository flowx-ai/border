# Open issues

Known, measured, and not yet fixed. Everything here has a number attached and something in
one of the repositories that produces it, because an issue list without measurements becomes
a wish list.

Ordered by what a caller would notice first, not by effort.

Last reviewed 2026-08-18, at `flowx-border` 0.2.0.

---

## 1. `moderation` reads account access as intrusion

**Fires on 5 of 12 ordinary support questions**, at 0.90 to 0.98. Four account-access
questions read as `cyber_intrusion`, including "How do I reset my password?" at 0.97, and
"How do I report a suspicious message I received?" reads as `sexual_exploitation` at 0.90.
That last one is a user trying to report abuse being labelled as the abuse.

Not a weak model. Mean per-language F1 0.9919 over 58 to 60 test examples per language,
positives 0.984 to 1.000 per label, and a false positive rate of 0.000 on all three mundane
registers. Every one of those is true and none covers account access, because the mundane
registers are informational, operational and transactional prose.

- **Where**: `tests/test_support_questions.py`, strict xfail.
- **Fix**: an account-access benign register in the corpus. Not a threshold: at its
  calibrated 0.84 it still fires on these.
- **Meanwhile**: disabled in both shipped policies, with the measurement in the policy
  comment.

## 2. `moderation` has two labels whose positives came back empty

`election_integrity` and `defamation` returned empty positives in the verification pass, 78
and 60 rows in the stratified sample. A label that trains on nothing is a label the detector
cannot report, and the aggregate does not show it.

- **Fix**: regenerate those two labels and re-verify before trusting any per-label figure
  for them.

## 3. `injection` still reads one imperative as an override

**1 of 12 ordinary support questions**, down from 7 of 12 in 0.1.0. The survivor is "Please
cancel my subscription." at `direct_injection` 0.9775, and it scores the same at 0.43 and at
0.95, so no threshold reaches it.

An imperative request to act on an account looks on the surface like an instruction
override, and the corpus has almost nothing of the shape: **2 rows of 35,025** match
account-access phrasing.

- **Where**: `tests/test_support_questions.py`, strict xfail.
- **Fix**: the same account-access benign register as issue 1, so the two should be done
  together.

## 4. `groundedness` is published, disabled, and one call in four is wrong

0.7381 on 42 hand-written probes with the rule layer in front, against 0.9471 on the
generator's own held-out split. Both are real and the gap is the point.

It was published because it is the only one of seven candidates whose verdict depends on the
source: 0.7681 against a source that contradicts the candidate, 0.0070 against an unrelated
passage, 0.8365 against one that states it, where the best three-way candidate answered
0.9991, 0.9994 and 0.0007 and was therefore inverted and source-blind.

Two corpus registers are the route to adoptable, and neither exists:

- **`unit_conversion`**: `24 months` against `two years`. Values match only after a
  conversion, which is why digitising the probes does not fix them. This is the only
  surviving hypothesis for the `paraphrase_support` failure, 1 of 6, after four others were
  eliminated by measurement.
- **`temporal_replacement`**: the shape of the blocking probe. 3,888 existing sources
  already carry both a time expression and a condition word, about 150 per language, so this
  register needs no new sources.

Known weakness meanwhile: false `not_grounded` on claims weaker than their source, 0.8625 on
the clearest case. Safe direction for a guardrail, still a cost, hence disabled.

- **Design**: `docs/groundedness-redesign.md` in the training repository.

## 5. Three detectors rest on single-digit per-language positives

`politeness`, `bias` and `gibberish`. Read their per-language scores as understated rather
than as ceilings, and reach for the corpus before the architecture.

The precedent: `nsfw` Maltese went from 0.000 to 1.000 on corpus size alone, after this
project had blamed the base model's pretraining in three places. `toxicity` came off this
list on 2026-08-14 at 197 to 209 positives per language.

## 6. `pii` frames, and two data files the generator needs

- **Regenerate the PII frames with varied surfaces.** Frame is what the label actually
  depends on: `CARD` scored 100% in the generator's own template, 32.5% with the neighbouring
  IBAN clause removed, and 18.3% in a sentence the generator never wrote. Template diversity
  first, then slots that vary independently.
- **A per-locale month name table**, so dates can be written as words. Every `DATE` in the
  frame corpus is a single numeric token, and held-out frames write `14 March 2024`, which is
  three. A tagger that has never seen a multi-token date cannot emit a multi-token span.
- **Greek and Bulgarian person names in their own script.**

## 7. The training repository has no off-machine copy

112 commits, and the findings in them cost GPU runs to establish. **The obstacle is not the
69 GB on disk.**

| | |
|---|---|
| repository total | 69 G |
| `.git` | 15 G |
| `artifacts_local`, mostly untracked | 41 G |
| files git tracks | 4.8 G |

`.git` is 15 G because model weights were committed: `exports/piiguard/model.onnx` at 1,058
MB, twice, plus safetensors of the same size. GitHub rejects any file over 100 MB, so a push
fails on those blobs regardless of the artifact directory.

Three routes, and the weights are all on Hugging Face now, so none of them loses anything
that is not already published:

1. **Rewrite history** to drop `exports/` and `*.safetensors`, then push. Keeps all 112
   commits. Invasive, and the commits are the valuable part, so this is the one worth doing
   properly rather than quickly.
2. **A fresh repository from the current tree.** Cheap, and loses the history, which is the
   only thing worth backing up.
3. **A non-git copy** to a bucket. Cheapest risk reduction today, needs no decision about
   history, and does not give code review or diffs.

Until one of these happens, one disk failure loses the record of what was tried and why.

---

## Closed while writing this

**The per-token latency slope was transposed.** `CLAUDE.md` said 1.636 ms/token and
`docs/reference/latency_sweep.json` said 1.663. Recomputed from the sweep's own single-window
points: the endpoint slope from 16 to 94 tokens is 1.6635 and least-squares over the seven
points is 1.6757, so neither supports 1.636. The JSON was right and the prose had the digits
swapped. Corrected in `CLAUDE.md` and in `src/flowx_border/detectors/pii.py`, which had
inherited it.

That makes it the fifth time a wrong number in this project reached a second file before
anyone noticed, which is why figures are read from generated reports rather than restated.
