# Open issues

Known, measured, and not yet fixed. Everything here has a number attached and something in
one of the repositories that produces it, because an issue list without measurements becomes
a wish list.

Ordered by what a caller would notice first, not by effort.

Last reviewed 2026-08-18, at `flowx-border` 0.2.1. Six open, one closed.

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

## 2. `moderation`'s verification pass disagrees with itself in three different ways

29,812 rows checked against a local `gpt-oss-safeguard:20b`. `border_train.read_disagreements`
classifies every row against the full verdict store rather than the report's 500-row sample:

| kind | rows | share | what it costs |
|---|---|---|---|
| agree | 25,901 | 0.8688 | |
| `label_replaced` | 1,898 | 0.0637 | a training signal, and a reader has to settle each one |
| `positive_called_empty` | 1,819 | 0.0610 | a hazard label on text that carries no hazard |
| `negative_given_a_label` | **183** | 0.0061 | **a hazard in the corpus as benign** |
| `label_added` | 11 | 0.0004 | nothing, these were applied |

Agreement reads 0.8688 here against the 0.8598 in
`reports/moderation_verification.json`, a difference of exactly 268 rows, which is
`rows_enriched` in `reports/moderation_enrichment.json`. The report is a snapshot from before
those enrichments and the module recomputes against the corpus as it stands.

Only the third kind is a safety question, and it is the one this issue did not mention until
2026-08-18.

**The checker almost never confirms `extremism`.** Per-label agreement, from
`reports/moderation_verification.json`:

| label | agree | differ | agreement |
|---|---|---|---|
| `extremism` | 54 | 1,285 | **0.040** |
| `sexual_exploitation` | 547 | 790 | 0.409 |
| `violent_facilitation` | 733 | 619 | 0.542 |
| `election_integrity` | 1,194 | 158 | 0.883 |
| `defamation` | 1,249 | 103 | 0.924 |

Only 9 of `extremism`'s 221 recorded disagreements are the checker returning nothing, so it is
not failing to see anything: it is naming something else. That is a taxonomy question rather
than a corpus one. Our 13 labels are ours, the checker reads a policy given at inference, and
where the two carve the space differently the disagreement is the mapping and not the row.
Worth resolving before any `extremism` figure is published, because a label the verifier and
the generator do not agree on is a label neither of them is measuring.

**`election_integrity` and `defamation` do have the empty-positives problem**, and it is the
opposite shape: 78 of 108 and 60 of 72 of their recorded disagreements are rows the generator
labelled and the checker read as carrying nothing. 1,819 rows corpus-wide are positives called
empty. Those are the ones to regenerate.

**The 183 rows the checker calls hazardous and the corpus calls benign are a definitional
split, not a checker error.** 74 of them sit in a `mundane_*` register, the generator's own
name for plainly benign prose, and 64 of those 74 are `fraud_deception`. The rows are
phishing-shaped: a security-update pretext with a same-day deadline and a `ResetPassword.it`
lookalike domain, a utility notice closing with "to avoid service interruption" and a phone
number, a plaintext server-room password. Ordinary transactional prose and a phishing lure
have the same surface form, so a register that asks for one produces the other.

The generator says which definition it applied, in its own `why` field: `keine Hilfsanfrage`,
`nessuna richiesta di aiuto`, `pas de demande d'aide`. It labels by whether the text **asks
for help with** a hazard, and 1,934 of 6,227 mundane rows justify themselves that way, so it
is the operative rule rather than an aside. `docs/moderation-taxonomy-proposal.md` defines
`fraud_deception` as "scams, phishing, social engineering, forged documents, money
laundering", which is a statement about content, and the checker reads it that way.

The library settles which reading has to hold. `moderation` declares `sides` of input and
output, and on the output side "does this ask for help" is not a coherent question, because an
LLM's output is not a request. So the generator's rule cannot be right for half of what the
detector does, and the 74 rows are corpus errors under the only reading that covers both
sides.

- **Where**: `uv run python -m border_train.read_disagreements --dump rows.json` in the
  training repo, which reads `reports/moderation_verify.gpt-oss-safeguard-20b.jsonl`.
- **Fix**: the mundane registers need a spec that forbids the phishing surface form, since
  asking for ordinary transactional prose is what produced it. The `*_near_miss` half of the
  183, 109 rows, is expected behaviour for a register whose job is to sit near the boundary
  and is a lower priority than the 74.
- **Owner decision, the same one `extremism` needs**: whether these 13 labels are about what
  a text contains or about what it asks for. Both halves of the corpus assume an answer and
  they assume different ones.

The verifier deliberately edits nothing, so the disagreement list is the artifact and reading
it is the work. The report's own `disagreements` list is a 500-row stratified sample, so its
shares are within that sample; the table above is corpus totals from the full store.

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

## 5. Three detectors rest on fewer than 20 test positives per language

Counted per language in the test split, because that is what a per-language F1 rests on.
`toxicity` set the bar at 19 to 20 when it came off this list on 2026-08-14, and three
detectors are still below it:

| detector | test positives per language | mean F1 | worst language | languages under 0.90 |
|---|---|---|---|---|
| `nsfw` | **9 to 10** | 0.9337 | `mt` 0.600 | 4 of 26 |
| `gibberish` | **9 to 12** | 0.9664 | `cs` 0.8696 | 1 of 26 |
| `politeness` | **15 to 16** | 0.9619 | `ga` 0.7879 | 2 of 26 |
| `toxicity` | 19 to 20 | 0.9915 | `sv` 0.9500 | 0 of 26 |
| `regulated_advice` | 23 to 24 | not scored here | | |
| `injection` | 40 to 42 | 0.9891 | `mt` 0.8817 | 1 of 26 |
| `moderation` | 58 to 60 | not scored here | | |
| `bias` | 76 to 80 | 0.9826 | `mt` 0.9419 | 0 of 26 |

**This issue named `bias` and omitted `nsfw` until 2026-08-18, and both halves of that were
wrong.** `bias` was retrained on the v2 corpus, 36,407 rows at 606 to 621 train positives per
language, and its thinnest language now carries 76 test positives. `nsfw` was left off because
its false-positive problem was fixed and its sample size was never separately tracked, so the
thinnest corpus in the set is the one this list did not mention. `CLAUDE.md` carried a third
version of the list naming `injection`, which has 40 to 42.

The figure worth acting on is `nsfw` Maltese: **0.600 on 10 test positives**, where one item
moves the score by 10 points. That is the same cell that went 0.000 to 1.000 on corpus size
alone in August after this project had blamed the base model's pretraining in three places, so
the 0.600 is as likely to be the sample as the language.

- **Where**: `data/{nsfw,gibberish,politeness}_test.jsonl`, counted by `labels` being non-empty.
- **Fix**: regenerate all three at the density `toxicity` and `bias` now have, then retrain.
  Needs the generation endpoint, so it queues behind the groundedness corpus.
- **Not a fix**: reading the minima as ceilings. Reach for the corpus before the architecture.

## 6. `pii` frames, and two data files the generator needs

- **Regenerate the PII frames with varied surfaces.** Frame is what the label actually
  depends on: `CARD` scored 100% in the generator's own template, 32.5% with the neighbouring
  IBAN clause removed, and 18.3% in a sentence the generator never wrote. Template diversity
  first, then slots that vary independently.
- **A per-locale month name table**, so dates can be written as words. Every `DATE` in the
  frame corpus is a single numeric token, and held-out frames write `14 March 2024`, which is
  three. A tagger that has never seen a multi-token date cannot emit a multi-token span.
- **Greek and Bulgarian person names in their own script.**

## 7. Local `.git` still holds the pre-rewrite objects

Minor, and the only remnant of what was issue 7. The training repository now has a private
remote at `flowx-ai/border-training`, 117 commits, and a fresh clone is 60 MB.

Getting there meant stripping committed model weights from history: `.git` had reached 15 GB
because `exports/piiguard/model.onnx` at 1,058 MB was committed twice, and GitHub rejects any
file over 100 MB, so the repository could not have had a remote at all. Nothing was lost,
because every one of those weights is published on Hugging Face and pinned by revision and
sha256, which says which bytes ran where a git blob only says somebody committed a file.

What remains is housekeeping. The local `.git` is still 15 GB: the old objects are unreachable
but retained via the reflog, deliberately, as the undo path for the rewrite. Once nobody wants
that undo:

```sh
git reflog expire --expire=now --all && git gc --prune=now
```

`artifacts_local/` is about 41 GB on disk, untracked, and some candidates there are the only
copy, so never `git clean -fdx` in that repository.

## Closed while writing this

**The per-token latency slope was transposed.** `CLAUDE.md` said 1.636 ms/token and
`docs/reference/latency_sweep.json` said 1.663. Recomputed from the sweep's own single-window
points: the endpoint slope from 16 to 94 tokens is 1.6635 and least-squares over the seven
points is 1.6757, so neither supports 1.636. The JSON was right and the prose had the digits
swapped. Corrected in `CLAUDE.md` and in `src/flowx_border/detectors/pii.py`, which had
inherited it.

That makes it the fifth time a wrong number in this project reached a second file before
anyone noticed, which is why figures are read from generated reports rather than restated.
