# Open issues

Known, measured, and not yet fixed. Everything here has a number attached and something in
one of the repositories that produces it, because an issue list without measurements becomes
a wish list.

Ordered by what a caller would notice first, not by effort.

Last reviewed 2026-08-19, at `flowx-border` 0.2.1. Seven open, two closed.

**Restructured 2026-08-18, and the count is the reason.** The list opened at seven items and
reached nine in a day, which reads as work going backwards. It was not: both additions were
things already true and merely unmeasured, and two sub-items closed inside what is now item 2.
But four separate items named four symptoms of one cause, a corpus that is thin in places and
the wrong shape in others, so they are now one item with four measured parts. Nothing was
dropped, and item 1 was added because the largest caller-visible number in the project was
recorded only in `CLAUDE.md` and in two strict xfails, and not here.

---

## 1. `pii` removes text from ordinary business prose, on 7.7 percent of rows

The largest caller-visible number in the project, and it was not on this list until 2026-08-18.
`pii` is enabled in both shipped policies, so this is behaviour a caller gets by default rather
than a figure in a report.

Measured by `tests/test_ordinary_text_sweep.py` over 234 ordinary rows in 26 languages, running
the whole shipped configuration on both sides:

| | 2026-08-18 | 2026-08-19 |
|---|---|---|
| rows where something is blocked or redacted | 0.162 | **0.0769** |
| `pii` fires | 0.261 | 0.261, against a 0.25 ceiling |
| `pii` damages a row | 0.150 | **0.0598** |
| leaked tokens | 0 | **0**, and 0 of 560 held-out spans survive verbatim |

**And looking for the residue found a disclosure, which was the more serious half.**
`entity_shapes.is_possible` required four digits for a `NATIONAL_ID`, on the stated premise
that every scheme in the 26 has them. An Azerbaijani identifier is seven alphanumerics with as
few as zero digits and an Italian codice fiscale sixteen with as few as one, so the gate
rejected them, and a rejected shape is **dropped**: the model found the identifier, tagged it
correctly, and the caller got it back.

| | gold national IDs | under four digits | end to end |
|---|---|---|---|
| `az` | 240 | **216 (0.900)** | 52 of 272 held-out spans survived verbatim |
| `it` | 240 | 78 (0.325) | |
| all 26 | 6,228 | 294 (0.047) | **1 of 272 after the fix** |

Pre-existing, not caused by the new bars: identical at 0.1912 with no `entity_thresholds` set.
The floor is now six alphanumerics, below Azerbaijan's seven, which is the shortest scheme in
the set. `tests/test_entity_shapes.py` pins both forms.

Worth knowing why "zero leaked tokens" did not catch it: that figure asks whether every gold
token is covered by *some* predicted span, and these spans were predicted before being dropped
a layer later. Coverage in the tagger is not survival through the library.

**Halved on 2026-08-19 with no retrain**, by `options.entity_thresholds: {person: 0.90}` in
`policies/default.yaml`. The firing rate is unchanged on purpose: the bar records what it
drops at `log`, so 86 findings are `date` at `flag`, 60 are
`pii_below_entity_threshold_person`, and only 42 are redactions.

The last row is what keeps this an over-redaction problem rather than a disclosure. Nothing
sensitive reaches a caller unredacted; the cost is text a caller wanted, removed.

**It was 0.756 on 2026-08-16 and the drop to 0.162 was three changes in a day**, none of them a
stoplist: `date: flag` in `policies/default.yaml`, an ISO 13616 minimum length on the IBAN rule,
and adopting the retrain that was already sitting in `artifacts_dates`. `person` went 0.581 to
0.128 and `national_id` 0.064 to 0.017.

**What remains is place names, and that is a different problem from the one that was fixed.**
The calendar words are gone: `Friday` and `Maerz` are no longer people. The residue, read off
the sweep:

| what it tags | as | in |
|---|---|---|
| `Regensburg`, `Passau`, `Straubing`, `Plattling`, `Vilshofen` | `person` | a German rail timetable |
| `Karlovo`, `Florenc`, `Fučíkovo`, `Stenløsevej`, `Midtjylland` | `person` | towns, districts, a street, a region |
| `„Академик Пейо Яворов“` | `person` | a Bulgarian school named after the poet, so arguably right |
| `800 123 456` | `phone` | a Czech freephone support line |

**`piiguard` has seven entity types and none of them is LOCATION**: CARD, DATE, EMAIL, IBAN,
NATIONAL_ID, PERSON, PHONE. `person` is also the only one with no shape to check, so
`entity_shapes.py` can reject a malformed IBAN and has nothing to say about a capitalised word.

**An ablation inside fixed frames found the cue, and it is not knowledge of place names.**

| filler | mid-sentence | sentence-initial |
|---|---|---|
| `Berlin`, `Paris`, `Siemens`, `Volkswagen` | never tagged | never tagged |
| `Regensburg`, `Valletta`, `Plattling` | 0.51 to 0.97 | not tagged |
| `Grelmshof`, invented | 0.89 to 0.97 | 0.70 |
| `Martin Weber` | 1.00 | 1.00 |

An invented token scores 0.97, so it is **an unfamiliar capitalised token mid-sentence**.
Sentence-initial is exempt because capitalisation there is orthography. The corpus says why:
75.3 percent of mid-sentence capitalised tokens in `piiguard_*` are part of an entity, and the
24.7 percent that are not are acronyms, German capitalised nouns and formal pronouns. A
name-shaped capitalised non-entity does not occur.

**So the fix was a bar on score, and deliberately not a stoplist of toponyms.** Place names are
common surnames and the model already separates the two by context:

| | as a place | the same token as a person |
|---|---|---|
| `Berlin` | not tagged | `Isaiah Berlin` 1.00 |
| `Paris` | not tagged | `Ms Paris` 1.00 |
| `Regensburg` | 0.68 | `Frau Regensburg` 1.00 |

A rule keyed on toponym shape would have turned a visible over-redaction into an invisible
hole, which `entity_shapes.py` refuses to do for exactly this reason.
`tests/test_entity_thresholds.py` pins both directions.

**What remains, and it is now a smaller question.** 13 `person` spans, 4 `phone`, 4
`national_id`. Most surviving `person` findings are places named after people, `Franjo Tudman`
at 0.977 and `Deak Ferenc` at 0.962, where the span does contain a person's name. The
`national_id` four are not identifiers at all: `EP2237/10` is a patent number, `LV-EWT2026` a
product code, `0800` a freephone prefix. Two open choices, both smaller than before:

- **A LOCATION type**, so a place has somewhere correct to go rather than the nearest
  proper-noun label. Arguably more correct, policy-visible, and a bigger decision than a bar.
- **Toponyms as entity-free corpus text**, which would move the remaining 13 down rather than
  needing a bar at all. Now a refinement rather than the fix.

- **Where**: `tests/test_ordinary_text_sweep.py`, two strict xfails carrying the numbers, split
  from the enforcing test so a `toxicity` or `nsfw` regression still fails something.
- **Not a stoplist.** `entity_shapes.py` refuses to drop a span, and the reason holds: a person
  really can be called April or Regensburg, and turning a visible over-redaction into an
  invisible hole is the wrong trade in a redactor.
- **The Czech freephone row is its own question**: whether a company's published support line is
  personal data at all. That is a taxonomy decision, not a model error.

## 2. The corpora, four measured gaps and one generation campaign

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
used to state it. See `reports/SEED_CONTROL.md` and issue 5.

- **Where**: `data/{nsfw,gibberish,politeness}_test.jsonl`, counted by `labels` being non-empty.
- **Fix**: regenerate all three at the density `toxicity` and `bias` now have, then retrain.
  Needs the generation endpoint, so it queues behind the groundedness corpus.
- **Not a fix**: reading the minima as ceilings. Reach for the corpus before the architecture.

### `pii` frames still need regenerating with varied surfaces

Frame is what the label actually depends on: `CARD` scored 100% in the generator's own
template, 32.5% with the neighbouring IBAN clause removed, and 18.3% in a sentence the
generator never wrote. Template diversity first, then slots that vary independently.

**The two data files this issue also asked for are built and wired**, so the regeneration is
all that is left and it will pick them up:

| | what it does | where |
|---|---|---|
| month names | dates written as words in 26 languages, so `DATE` is a multi-token span at all | `border_train/month_names.py`, called by `pii_fill.make_date` at a 0.5 share |
| names in script | Greek and Bulgarian people written in Greek and Cyrillic, surname agreeing in gender | `_IN_SCRIPT_NAMES` and `make_person` in `border_train/pii_fill.py` |

Both were listed here as outstanding until 2026-08-18 and both had landed. The month table
had no test until then either, and writing one found that Finnish generated `14. maaliskuu
2024` half the time, a bare nominative no Finnish writer produces, because the partitive was
built in the template over the nominative stem while the genitive column already held it
correctly. One written Finnish date exists across the 26,455 rows of `pii_frames` and
`piiguard`, so the fix precedes any corpus that uses it.

- **Where**: `tests/test_month_names.py` and `tests/test_person_names.py` in the training
  repo, 459 and the person set respectively, parametrised over all 26.
- **Fix**: regenerate the frames. `DATE` is the type to read afterwards, since it scored
  typed F1 0.0000 with every gold span missed on held-out frames, and a multi-token date is
  the thing it had never seen.

## 3. `injection` still reads one imperative as an override

**1 of 12 ordinary support questions**, down from 7 of 12 in 0.1.0. The survivor is "Please
cancel my subscription." at `direct_injection` 0.9775, and it scores the same at 0.43 and at
0.95, so no threshold reaches it.

An imperative request to act on an account looks on the surface like an instruction
override, and the corpus has almost nothing of the shape: **2 rows of 35,025** match
account-access phrasing.

- **Where**: `tests/test_support_questions.py`, strict xfail.
- **Fix**: the same account-access benign register as item 2's first part, so the two should be done
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

## 5. No retrain delta in this project has a measured noise floor

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

## 6. `topic_scope`'s shipped threshold was below its own score floor

Fixed 2026-08-19 and kept on the list because what it says about the other thresholds is not
yet checked.

`topic_scope` emits a rescaled cosine, `(cos + 1) / 2`, and both shipped policies set a
threshold of **0.45**, which is a raw cosine of -0.10. Over the 408 rows of the training
corpus's test split against a 15-node taxonomy, the lowest score any text achieves is 0.6674,
so **408 of 408 cleared it**. The threshold rejected nothing and firing was decided entirely by
whether the nearest node happened to be `disallowed`. Under `policies/bfsi.yaml`, where
`on_fail` is `block`, that is a refused response for an input the detector had no opinion about.

On the 78 rows that belong to no node at all:

| bar | in-scope kept | out-of-scope kept | separation |
|---|---|---|---|
| 0.45, as shipped | 1.0000 | 1.0000 | **0.0000** |
| 0.80 | 0.9600 | 0.7692 | 0.1908 |
| **0.85, now shipped** | 0.8000 | 0.2692 | **0.5308** |
| 0.87 | 0.6857 | 0.0897 | 0.5960 |

**Why the published eval could not see it.** `topic_scope_eval.json` reports `top1_accuracy`,
which asks *which* node is nearest and never *whether any* is near enough, so a rank metric
cannot see a threshold that never binds. The file's own note that its 78 out-of-taxonomy rows
are "never scored, which is half of what it is for" was the more important sentence in it.

**Two of my own measurements were wrong on the way here** and both are worth keeping. I first
built the taxonomy with `path.replace("/", " ")` as the node description and concluded from it
that no threshold could separate the registers, because out-of-taxonomy text scored *higher*
than in-scope. With the corpus's real descriptions the ordering reverses. And a margin sweep
read 1.0000 at every bar because it counted over one list and divided by another's length; a
sweep returning the same number for every threshold should have stopped me sooner.

- **Where**: `tests/test_topic_scope_threshold.py`. The fast test needs no model and asserts
  every shipped `topic_scope` threshold sits above the recorded floor.
- **What is left**: the same check has not been run for the other detectors' thresholds. A
  classifier's sigmoid does reach 0, so the fault is specific to a rescaled-cosine score, but
  "probably fine" is what 0.45 was.
- **And the bar is taxonomy-dependent**: measured on 15 nodes, and more nodes mean more chances
  of a spurious near-match, so a deployment should re-sweep it.

## 7. Four published models cannot be re-verified against a stricter export gate

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
  item 2 and `moderation` on the one beside it, and a retrain writes both halves.
- **`topic_scope` needs no action, established 2026-08-19.** It is unconfigured in both shipped
  policies and is T3, so nothing in the shipped configuration loads it and its missing fp32
  half cannot affect a caller. Its manifest is also the most complete of the set: it records
  cosine-to-torch for both halves and that the int8 export moved 2 of 200 top-1 taxonomy
  nodes. Nothing recovers its weights, and nothing needs to.
- **Then keep them.** A run writes `model.safetensors` and `run.json` at the artifact root
  today, so this is a retention habit rather than a code gap. About 1 GB per model.

## Closed while writing this

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
