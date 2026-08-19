# The ordinary-text rows the sweep measures against

`mundane_rows.json` is a snapshot of the corpus half of `tests/test_ordinary_text_sweep.py`'s
input: 208 rows, 52 from each of the four `mundane_*` registers, 8 per language across 26.
`taken_from` records the corpus `prompt_version` and `content_sha256` the rows came from.

## Why a snapshot exists

The sweep reads `data/moderation_train.jsonl` from the training repository, which is
regenerated whenever a register changes. On 2026-08-19 that happened, and every number the
sweep reports moved with no code change and no model change: `regulated_advice` from 0.145 to
0.829 and `bias` from 0.004 to 0.068, over its ceiling.

Neither was a regression. `ordinary_rows()` took the first eight rows per language **in corpus
order**, and the corpus had begun writing the newly added `mundane_account_access` first, so
all 208 rows became account-access requests. The sweep stopped measuring ordinary text and
measured one register instead, while looking exactly like four detectors going wrong.

Two things followed. The sampler is now stratified round-robin across registers, so the sample
cannot move when a generator's register order does. And this file records which corpus the rows
came from, so a figure can be traced to its input.

## Refreshing it

Deliberately, not incidentally: regenerate from the live corpus, re-read the numbers, and
commit both together. A refresh that changes the rows and leaves the recorded ceilings alone is
the failure above with extra steps.

## The open question this does not settle

**Whether the generated mundane rows are valid negatives at all.** Measured per register on the
balanced sample, every detector fires on 0 of the 26 hand-written sentences and heavily on the
generated ones:

| detector | hand-written | account_access | informational | operational | transactional |
|---|---|---|---|---|---|
| `regulated_advice` | 0.000 | 0.923 | 0.250 | 0.481 | 0.712 |
| `pii` | 0.000 | 0.231 | 0.346 | 0.404 | 0.827 |
| `bias` | 0.000 | 0.058 | 0.000 | 0.000 | 0.019 |

A transactional notice naming a customer and an amount **should** make `pii` fire, so 0.827
there is partly correct behaviour rather than noise. This project's own rule is that where the
two sources disagree the hand-written ones are the evidence, and they disagree completely. So
some of these ceilings may be measuring the corpus rather than the detectors, and that is a
judgement to make deliberately rather than by adjusting a number.
