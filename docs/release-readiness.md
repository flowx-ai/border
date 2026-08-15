# Open items before flowx-border goes public

Written 2026-08-15. Every number here comes from the repository or from a measurement
recorded in it, and the ones that are guesses say so.

## State at the 2026-08-15 machine move

Everything was stopped cleanly for a move to a new machine. All three repos are committed
and clean, and all four GCP VMs are TERMINATED. This section is what was in flight, so a
session picking this up cold knows what resumes and what does not.

**Where the work only exists once.** `training` has no git remote at all: 82 commits and a
35 GB working tree, of which 21 GB is `artifacts_local` model weights that git ignores by
design. `library` has a remote but no upstream on `main`, with 61 commits not on origin.
`landing_page` is 19 commits ahead. So pushing the repos would still not carry the weights,
and a disk copy is the only copy of most of this.

**Stopped mid-run and resumable.** Moderation verification against the local
`gpt-oss-safeguard:20b`, at 10,006 of 29,825 rows. The cache is committed at
`training/reports/moderation_verify.gpt-oss-safeguard-20b.jsonl`; rerunning
`border_train.verify_moderation` skips what is already there. Nothing was lost by stopping.

**Waiting on the owner.** `training/reports/extremism_label_sheet.csv`, 52 rows, two per
language, with an empty `is_violent_extremism_y_n` column. `moderation` must not be trained
until it comes back, for the reason in section 2.

**Finished and not yet adopted.** `injection` v3 is trained and exported on
`border-train-l4` in `us-east1-b`, under `artifacts_new/injection-full`. That VM is
stopped. `border-l4-b` in `us-east1-c` hit a STOCKOUT the same day.

## Where it stands

All seven build phases are tagged, `phase-0` to `phase-7`. The library is complete: 28
detectors catalogued, 27 implemented, and **18 run on a fresh install with no model
download**. The suite is 1,925 passing with the local models present.

So the code is not the blocker. What is left is models, publication, and a handful of
things that only matter because the repository becomes public.

## 1. Models

| detector | state | what is left |
|---|---|---|
| `injection` | **trained and exported today**, mean F1 0.9703, worst `mt` 0.727, INT8 gate passed | adopt it into `artifacts_local`, about ten minutes |
| `moderation` | corpus complete, 29,825 rows, 26 languages, 12 labels | the extremism question below, then train |
| `groundedness` | four candidates, none adopted | needs a new kind of evaluation, not another run |
| `piiguard` | new frame corpus filled, 21,164 examples, 11.8 percent entity-free | the OpenNER trainer expects its own template-generated data; feeding it this corpus is unwritten plumbing, a couple of hours |
| `regulated_advice` | trained, ships unavailable | publication only |
| `politeness`, `bias` | shipped, but single-digit positives per language | corpus regeneration, endpoint time |

**`groundedness` is the one with no route yet, and it is worth being plain about.** Four
models have failed the same probe: a source says withdrawals cost a fee for twelve months
and are free after, the candidate says they are free from day one, and the model calls it
grounded. The readings were 0.9906, 0.9987, 0.9594 and 0.9995. More epochs made it worse.
A class weight fixed everything the corpus teaches and nothing it does not. Adding the
missing register produced a model that scores 0.9303 on that register's own test split and
still catches one dropped condition in three.

The obstacle is that a test split drawn from the same generator as the training data
cannot tell a memorised register from an understood one. Until there is an evaluation the
generator cannot ace, another training run is not evidence. This is the only item on the
list where I cannot give a date.

## 2. The extremism question, which is yours to settle

Verification found that a third of `extremism` positives carried no harm label at all:
manifestos, flags, logos, songs, party meetings, one naming a real opposition party. The
taxonomy asks for *violent* extremism and the generator heard "underground".

I tightened the taxonomy, and it half-worked. The near-miss negatives are now exactly
right, a peaceful manifesto for human rights and a de-radicalisation lecture. The
positives still include some with no violence established.

**The re-measurement is not usable and the reason matters.** The verifier builds its
prompt from the taxonomy, and I edited the taxonomy, so the generator and the verifier now
share the same boundary and agree by construction. 33 percent became 31 percent, and that
comparison means nothing.

`reports/extremism_label_sheet.csv` is 52 rows, two per language so every language is
represented, with an English gloss and an empty `is_violent_extremism_y_n` column. That
gives a boundary neither model supplied. With it I can say what the real rate is, decide
whether the register needs another pass, and train `moderation` on a corpus that is not
teaching a detector to flag opposition political organising in 26 languages.

## 3. Publication

Nothing is on Hugging Face yet. That was deliberate: a single release at the end, decided
2026-08-11.

- **Twelve model ids are registered as unpublished**, including every classifier the
  library loads locally. Publishing them turns a fresh install from 18 detectors into 27.
- **No repository declares a `license:` field**, even where the card states Apache-2.0.
  The registry cannot attest a licence that is not declared.
- **The `cee-pii` and `scam-guard-qwen06b` cards still contain pre-publication HTML
  comments** reading "NOT YET UPLOADED".
- **`piiguard`'s tags advertise two locales.** It was trained on nine and retrained on 26.

The last three are minutes of work and all four are release blockers.

## 4. The repository becoming public

Two mechanical gates already run in CI: no em-dashes, and an SPDX header on every source
file. Both pass. The README's numbers are pinned to `docs/reference/performance.json` by
`tests/test_readme.py`, and a published score whose artifact has been swapped fails
`tests/test_performance.py`.

What is not mechanical is a read-through of every comment, docstring and commit message
against the standard in CLAUDE.md, since all of it becomes a public claim. That is worth
one deliberate pass rather than trusting that each was written carefully at the time.

## 5. Smaller open items

- `docs/porting-guardrails-validators.md` names candidates for detectors that would
  complete the set. The owner queued a proposal with a tier and a budget each, after the
  port rather than folded into it. Nothing blocks it: it needs no compute.
- The landing page has an outstanding reconcile against the `guard-amber-web` reference.
- `NATIONAL_ID` and `DATE` remain weak in `piiguard` and are generator work: `DATE` tags
  `14`, `March` and `2024` as three spans rather than one, and `NATIONAL_ID` is where the
  model puts any digit run it does not recognise.

## What I would do in what order

1. The 52 labels, because they unblock a whole detector and cost an evening.
2. Adopt `injection`, which is finished and sitting there.
3. The three hub hygiene fixes, which are minutes each.
4. `piiguard` plumbing, then train, since the frame corpus is the deepest measured fix.
5. The public read-through, last, when nothing else will churn the text.

`groundedness` sits outside that order until the evaluation problem is solved. Shipping it
unavailable is the honest state and costs nothing: the detector is implemented and refuses
loudly rather than silently passing.
