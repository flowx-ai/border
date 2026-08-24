# Open issues

Known, measured, and not yet fixed. Everything here has a number attached and something in
one of the repositories that produces it, because an issue list without measurements becomes
a wish list.

Ordered by what a caller would notice first, not by effort.

Last reviewed 2026-08-20, at `flowx-border` 0.3.0. Four open, six closed.

**Three items closed the same day, and the count went from seven to four.** `pii`
over-redaction, the largest caller-visible number in the project, closed with a LOCATION
entity type rather than the score bar that had been holding it down. `topic_scope`'s
threshold closed once the other twelve were checked and found not to share its fault.
`regulated_advice`'s split closed with a retrain on the corrected corpus, published. None
of the three closed by lowering a bar or narrowing a claim; each closed because the thing
underneath it changed. What remains open is one line inside the closed `regulated_advice`
entry: three other corpora still carry a split written before the same fix and are not
re-split until they are next retrained.

**Restructured 2026-08-18, and the count is the reason.** The list opened at seven items and
reached nine in a day, which reads as work going backwards. It was not: both additions were
things already true and merely unmeasured, and two sub-items closed inside what is now item 2.
But four separate items named four symptoms of one cause, a corpus that is thin in places and
the wrong shape in others, so they are now one item with four measured parts. Nothing was
dropped, and item 1 was added because the largest caller-visible number in the project was
recorded only in `CLAUDE.md` and in two strict xfails, and not here.

---

## 1. The corpora, four measured gaps and one generation campaign

These were items 1, 2, 5 and 6 until 2026-08-18. They are one item because they are one cause:
a corpus that is thin in places and the wrong shape in others. Every part needs the generation
endpoint, so they queue rather than compete, and a single campaign addresses all four.

The four, ordered by what a caller would notice:

### `moderation` reads account access as intrusion

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

### The verification pass disagrees with itself in three different ways

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

### Three detectors rest on fewer than 20 test positives per language

Counted per language in the test split, because that is what a per-language F1 rests on.
`toxicity` set the bar at 19 to 20 when it came off this list on 2026-08-14, and three
detectors are still below it:

**Closed on 2026-08-19, and the corpora are regenerated and retrained.** Kept because the rule
that produced the problem is still in `CLAUDE.md` and still wrong for a two-register detector.

| detector | positives per language | per-language mean F1 |
|---|---|---|
| `nsfw` | 9 to 10 -> **23 to 24** | 0.9337 -> 0.9738 / 0.9653 |
| `gibberish` | 9 to 12 -> **28 to 32** | 0.9664 -> 0.9915 / 0.9892 |
| `politeness` | 15 to 16 -> **20 to 21** | 0.9619 -> 0.9790 / 0.9844 |

Two seeds each, five of six labels above the measured noise floor, every export gate clean at
0 of 300 decisions changed, and `nsfw` Maltese's seed spread down from 0.3294 to 0.1179. Not
adopted: see `reports/THICK_CORPORA.md`. What is left is a calibrated threshold that is a seed
artifact for two of the three, 0.63/0.86 for `nsfw` and 0.03/0.40 for `politeness`, because
their validation curves are flat.

The original table, for the record:

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

**The `nsfw` Maltese cell was measured on 2026-08-18 and it is worse than thin, it is
unstable.** Two runs on the identical corpus at seeds 42 and 1337 read Maltese as **0.8000 and
0.4706**, a spread of 0.3294 on those 10 test positives, with the shipped model's 0.6000
between them. This paragraph called 0.600 "the figure worth acting on" and said one item moves
it by 10 points; the seed alone moves it by 33. It is a property of a draw, not of Maltese, and
it must not be quoted as a score.

The diagnosis is unchanged and is in fact what the spread demonstrates: 10 positives cannot
support a per-language figure. What changed is that the number naming the problem cannot be
used to state it. See `reports/SEED_CONTROL.md` and issue 4.

- **Where**: `data/{nsfw,gibberish,politeness}_test.jsonl`, counted by `labels` being non-empty.
- **Fix**: regenerate all three at the density `toxicity` and `bias` now have, then retrain.
  Needs the generation endpoint, so it queues behind the groundedness corpus.
- **Not a fix**: reading the minima as ceilings. Reach for the corpus before the architecture.

### `pii` frames needed regenerating with varied surfaces, and both target types recovered

Closed 2026-08-20. Frame was what the label actually depended on: `CARD` scored 100% in the
generator's own template, 32.5% with the neighbouring IBAN clause removed, 18.3% in a
sentence the generator never wrote, and `DATE` scored typed F1 0.0000 on held-out frames with
every gold span missed. Regeneration was the fix and it landed as a side effect of a
different repair: `slots_out_of_order` was rejecting 1,260 of 6,456 items in a paid batch
because slot order was read from the request rather than the reply, and fixing that recovered
a corpus large enough to ship, which also broke the fixed IBAN-then-CARD adjacency the old
templates always produced. `LOCATION` joined as an eighth type in the same retrain. Re-run on
truly held-out frames, `border_train.heldout_ner_eval` against `artifacts_local/piiguard-full`:

| type | before | after |
|---|---|---|
| `CARD` | 18.3% in a novel sentence | **F1 0.8170, recall 1.0000**, precision 0.6906 |
| `DATE` | F1 0.0000, every span missed | **F1 1.0000** |
| `PERSON`, `EMAIL`, `IBAN`, `PHONE` | 1.0000 | 1.0000, unchanged |

CARD's recall is perfect and its precision is not: 233 spurious spans against 520 gold, so it
over-tags card-shaped digit runs. `checksummed.py` already validates any redacted PAN
independently, so an over-tagged span costs a caller unnecessary redaction rather than a
leak, the same direction of error this project's own bar decisions keep choosing. Not chased
further here because nothing measured says it is worse than before, only that it is now
visible.

**Two things this measurement could not answer, both left as smaller open work rather than
folded into this closure.** `NATIONAL_ID` remains weak on held-out frames, F1 0.1429, which is
the same long-standing gap `CLAUDE.md` documents and this regeneration did not target.
`LOCATION` read F1 0.0000 on held-out frames with **zero gold spans**, an artifact of the
harness rather than the model: `heldout_ner_eval`'s hand-written probes predate the type and
none of them carry a place name. That is a vacuous measurement in exactly the shape this
project keeps finding, so it is named rather than reported as a score. Adding a handful of
hand-written LOCATION probes to the held-out set is the next small step, not a retrain.

Also found and fixed the same day: `heldout_ner_eval.py`'s "languages where it tags things
that are not there" table read `by_locale`, which sums every axis, printed directly under a
header about the 26-row entity-free-prose axis specifically. It showed 8 languages at 8 to 11
spans each, which was CARD's broader over-tagging on non-zero axes leaking into a section
about clean prose. A `by_locale_zero` cut, scoped the same way the summary line above it
always was, now agrees with it: 2 languages, 1 span each.

The two data files this issue also asked for, month names and in-script person names, were
built and wired before this and are unaffected by anything above.

- **Where**: `tests/test_month_names.py` and `tests/test_person_names.py` in the training
  repo. `artifacts_local/piiguard-full/heldout_ner_eval.json` carries the measurement above.

## 2. `groundedness` is published, disabled, and one call in four is wrong

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

**The two "missing" registers were not missing, and the 0.9471 was measured on a split that
could not see them.** Found 2026-08-20, applying the same domain-aware writer fix that closed
item 7 below to this corpus's 5 domains: 4 of them were absent from val or test entirely.
`unit_conversion` and `temporal_replacement`, named above as the route to adoptable, already
exist in the corpus, 368 and 374 test rows once the split is corrected, and had simply never
reached an evaluation. Re-split with `border_train.resplit`, `data_binary/` regenerated from
it, and this artifact's own weights, unchanged, re-evaluated with no retraining:

| register | accuracy, corrected split |
|---|---|
| `temporal_attribution` | **0.6402** |
| `temporal_replacement` | 0.7781 |
| `unit_conversion` | 0.7880 |
| `numeric_conflict` | 0.9632 |
| `negation_conflict` | 0.9836 |
| `lexical_overlap` | 0.9861 |
| `scope_conflict` | 0.9929 |
| `unstated` | 0.9954 |

Pair accuracy falls from 0.8991 to 0.8015. Five registers cluster at 0.96 to 0.995 and three,
exactly the ones the old split under-tested, sit at 0.64 to 0.79. The model has not changed;
what it can do is now measured on the cases it was weakest at rather than mostly on the ones
it already handled. `artifacts_local/groundedness-full/SPLIT_CORRECTED_2026-08-20.md` in the
training repository carries the same table.

**Read this as the corpus problem restated with better data, not as solved.** The two
registers exist and are measured, and the measurement says the model is still weak on both,
`temporal_attribution` worst of all at 0.6402. So the corpus work is not "generate two more
registers", it is "these two registers say the model needs work", which is a retrain question
rather than a data-generation one.

Also renamed the artifact directory from `groundedness-binary-2026-08-17-adopted` to
`groundedness-full`, matching every other adopted artifact. It did not match before, which is
why `docs/reference/performance.json` reported `metrics: null` for a model that is genuinely
published and shipped, only disabled by default. That silence is closed too, and the library's
published table now carries this detector's numbers for the first time.

## 3. No retrain delta in this project has a measured noise floor

A seed control was run for the first time on 2026-08-18: the same `moderation` corpus, the
same hyperparameters, seed 42 against seed 1337. Per-label F1 moved by a mean of 0.0073 and a
maximum of **0.0188** between two runs differing in nothing but the seed.

Every retrain judgement in this project predates that measurement. The 2026-08-14 table in
`CLAUDE.md` records `nsfw` +0.0158 and `bias` +0.0206 in mean per-language F1, both at or
under that maximum, and `toxicity` +0.0311 above it. No seed control was run for any of the
three.

This does not say those retrains failed. It says a single run cannot distinguish an effect
from a reseed, and every comparison so far has been a single run. The concrete case is the one
to hold: on the enriched `moderation` corpus, seed 42 reads the weakest language as `mt`
0.9744 against the shipped 0.9655, which reads as the corpus fixing Maltese, and seed 1337
reads `mt` 0.9580. The two straddle the baseline.

- **Where**: `border_train.compare_runs`, and `reports/moderation_seed_control.json`.
- **Fix**: two seeds per retrain before reporting a delta. It doubles the GPU cost of a
  10-minute run, which is the cheapest thing on this list.
**That non-transferability was then measured, and the guess held.** A second control on
`nsfw`, whose per-language cells hold 9 to 10 positives against `moderation`'s 130 per label:

| | `moderation` | `nsfw` |
|---|---|---|
| per-language spread, mean / max | 0.0052 / 0.0252 | **0.0389 / 0.3294** |
| per-language mean F1, spread between runs | 0.0007 | 0.0171 |
| calibrated threshold, two seeds | 0.83, 0.85 | **0.84, 0.94** |

Thirteen times wider on the widest cell. Two further consequences, both concrete:

- **`nsfw`'s recorded retrain gain is inside its own floor.** +0.0158 in mean per-language F1
  against a measured 0.0171 spread between seeds on identical data.
- **A calibrated threshold is a seed artifact where the corpus is thin**, and
  `policies/default.yaml` takes the library's default from it. `moderation` is stable at 0.83
  and 0.85; `nsfw` gives 0.84 and 0.94 against the shipped 0.76.

- **Still not transferable as a number.** The floor scales with the test split and the splits
  differ by an order of magnitude across detectors, so re-measure per detector rather than
  reusing 0.0188 or 0.3294.

## 4. Four published models cannot be re-verified against a stricter export gate

Re-checking a quantised export needs both halves, fp32 and quantised. `CLAUDE.md` already
records this for `groundedness`: "an artifact whose fp32 is gone cannot be re-verified when the
gate gets stricter, which is exactly when you want to." Audited against `registry.MODELS` on
2026-08-18, it applies to four of the eleven published models.

| | fp32 half | `run.json` |
|---|---|---|
| `bias`, `groundedness`, `piiguard` | kept | kept |
| `nsfw`, `toxicity`, `regulated_advice`, `injection` | **recovered from the VM 2026-08-18** | 1 of 4 |
| `gibberish`, `politeness`, `moderation`, `topic_scope` | **gone** | 1 of 4 |

The four recovered were on `border-l4-x` and are now in `artifacts_local`, matched to the
shipped model by identical per-language eval table rather than by directory name. That check
mattered: `regulated_advice` had two candidates whose mean F1 differed by 0.0001, 0.9950 and
0.9951, at different thresholds, so the mean could not pick between them and the table could.
`nsfw` also looked absent on a first pass because the audit guessed the directory name and
`groundedness` looked absent for the same reason.

The four that are gone were trained on a VM that no longer exists. Each still has its
`export_manifest.json`, so what the gate measured at the time is on record; what cannot be done
is running a stricter gate. The gate did get stricter once, on 2026-08-15, when p99 probability
drift was added.

- **Where**: `artifacts_local/<detector>-full/model.safetensors`, and `registry.MODELS` for
  what is published.
- **Fix, three of the four for free**: `gibberish` and `politeness` are on the retrain list in
  item 1 and `moderation` on the one beside it, and a retrain writes both halves.
  `moderation` itself is done as of 2026-08-19: both seeds of the v4 retrain kept their
  safetensors and their int8 export, so it has both halves for the first time.
- **`topic_scope` needs no action, established 2026-08-19.** It is unconfigured in both shipped
  policies and is T3, so nothing in the shipped configuration loads it and its missing fp32
  half cannot affect a caller. Its manifest is also the most complete of the set: it records
  cosine-to-torch for both halves and that the int8 export moved 2 of 200 top-1 taxonomy
  nodes. Nothing recovers its weights, and nothing needs to.
- **Then keep them.** A run writes `model.safetensors` and `run.json` at the artifact root
  today, so this is a retention habit rather than a code gap. About 1 GB per model.

## Closed while writing this

**`pii` over-redaction on ordinary text is fixed, not merely reduced.** The largest
caller-visible number in the project. It went 0.756 (2026-08-16) to 0.162 to 0.0769 to
0.2051 as the measurement itself got more honest (a corpus artifact swap, then a
row-sampling fix that this list did not catch until the numbers were re-taken), and the
open question at every one of those points was the same: `piiguard` had seven entity
types and none of them was LOCATION, so a place name had nowhere correct to go and landed
in `person`. A score bar at 0.90 papered over it from 2026-08-19, catching 30 of 43
damaging findings at a measured cost of nothing to real names, but two open choices
remained: a LOCATION type, or toponyms as entity-free corpus text.

Closed 2026-08-20 by the first choice. The retrain gained `LOCATION` as an eighth type,
published as `flowxai/piiguard` revision `ed1fa965`, and every `person` finding across
the 234-row sweep is now checked by hand and is a genuine person: zero toponyms.
`entity_thresholds: {person: 0.90}` is removed from both shipped policies, because its
whole job was filtering toponyms and there are none left to filter.

    ordinary-text pii damage         0.1709 -> 0.1282
    pii:person findings, all genuine either way    66 -> 56
    pii:national_id false positives                8 -> 4

0.1282 is higher than 0.1026, the number measured the same day with the bar still in
front of the new model, and that is not a step backward: the damage metric counts
over-redaction only and cannot tell a real name correctly redacted from one incorrectly
left alone. The 18-finding gap between 38 and 56 is exactly the real names, `Tiina`,
`Jänis`, `Anders`, `Müller`, `Marinescu`, that the bar was silently demoting to a logged
note instead of a redaction. Verified against the library's own suite before publishing,
and again against the live pin after: 2096 passed. See `tests/test_entity_thresholds.py`
and the superseded artifact's `WHY_SUPERSEDED.md` in the training repo.

**`topic_scope`'s shipped threshold was below its own score floor, and the other twelve
thresholds in the library do not share the fault.** 0.45 against a floor of 0.6674 meant
408 of 408 test rows cleared it regardless of content, so firing was decided entirely by
which taxonomy node was nearest. Fixed to 0.85 on 2026-08-19, separation 0.0000 to 0.5308.
Checked by construction rather than by sweeping (a sweep found only artifacts of a thin
sample on the other eleven): every other shipped `threshold` sits on a score that reaches
0, sigmoid, a difflib ratio, or a similarity ratio, and `topic_scope`'s rescaled cosine
was the only one that could not. `tests/test_topic_scope_threshold.py` pins the floor.

**`regulated_advice` published a macro of 0.995 while its largest label, `financial_advice`,
had never been scored, and the corrected model is now published.** The split was cut along
domain lines: 9 of 12 domains landed in exactly one split, and the label with 2,542 train
rows had zero test rows, so its `f1=0.0` was a division by nothing rather than a score.
Fixed in the writer, `border_train/datagen/base.py::write`, forming units before
stratification and keying on `(language, domain)`, with coverage of every language,
register, domain and label asserted as a guard.

Retrained at two seeds and published as `flowxai/regulated-advice` revision `5141792f`.
`financial_advice` reads 0.8927 at a support of 260, and the detector's ordinary-text fire
rate falls from 0.5256 to 0.0598, under its 0.10 ceiling, so it moved off the enforced
`KNOWN_OVER` list. The collector also gained a caveat for any zero-support label and for
the gap between a per-language macro and its weakest per-label score, since the same
question, "does it fire" versus "which label", is general across the five multi-label
heads and not unique to this one.

Three other corpora have more than one domain and their splits on disk predate the writer
fix: `topic_scope` with 16, `groundedness` with 5, `injection` with 2. Under the old
writer 4 of `groundedness`'s 5 domains are absent from its test split, so its published
figures describe one document type out of five. A corpus is only re-split when it is
regenerated, so this stays open until each is deliberately retrained, tracked as part of
item 1's generation campaign rather than as its own line.


**`injection` no longer reads an imperative as an override, and it was already fixed when this
item still said otherwise.** Measured 2026-08-19 against the shipped v5, revision `e2dd543f`:
**0 of 12** ordinary support questions fire, and `"Please cancel my subscription."`, the
survivor this item was written about, produces no finding at all rather than
`direct_injection` 0.9775.

    v3   7 of 12   every benign register was conversational prose, so an imperative
                   account request was out of distribution
    v4   1 of 12   technical registers added for an unrelated failure incidentally helped
    v5   0 of 12   after mundane_account_access joined the shared MUNDANE_REGISTERS

The corpus carries 1,862 rows in that register across all 26 languages, 61 of them with a
cancellation phrasing labelled benign, against 2 rows in 35,025 before. `tests/
test_support_questions.py` records the same three-version history beside the test, which is
where the discrepancy showed: the test had been un-xfailed when v5 landed and this list was
never updated. **Read the test, not the issue.**

The same register also closed the `moderation` half on the same day, 5 of 10 to 0, so the two
were done together as this item said they should be.


**The pre-rewrite objects are gone and `.git` is 64 MB.** Was 15 GB, because
`exports/piiguard/model.onnx` at 1,058 MB had been committed twice before the history was
rewritten. The unreachable objects were retained deliberately as the undo path for that
rewrite; verified first that the remote carries all 145 commits and that nothing exists only
locally, then `git reflog expire --expire=now --all && git gc --prune=now`. History intact,
working tree untouched, `size-pack` was 2.38 GB of the 15.


**The per-token latency slope was transposed.** `CLAUDE.md` said 1.636 ms/token and
`docs/reference/latency_sweep.json` said 1.663. Recomputed from the sweep's own single-window
points: the endpoint slope from 16 to 94 tokens is 1.6635 and least-squares over the seven
points is 1.6757, so neither supports 1.636. The JSON was right and the prose had the digits
swapped. Corrected in `CLAUDE.md` and in `src/flowx_border/detectors/pii.py`, which had
inherited it.

That makes it the fifth time a wrong number in this project reached a second file before
anyone noticed, which is why figures are read from generated reports rather than restated.
