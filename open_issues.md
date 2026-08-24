# Open issues

Known, measured, and not yet fixed. Everything here has a number attached and something in
one of the repositories that produces it, because an issue list without measurements becomes
a wish list.

Ordered by what a caller would notice first, not by effort.

Last reviewed 2026-08-24, at `flowx-border` 0.3.0. One open, nine closed. The one left is a
retrain with no easy path: `groundedness`'s weak registers need real ML work, not generation
or bookkeeping.

**The corpora item's last two parts closed the same day.** `extremism`'s near-zero checker
agreement turned out to be expected disagreement rather than a defect on a second look, and
is documented rather than fixed. `positive_called_empty`'s dominant cause, victim-support and
reporting text labelled as if it were the hazard it described, was a real, measured defect
in the shared generation prompt and was fixed: the corpus regenerated whole and
`flowxai/moderation` republished. All four of item 1's measured parts are closed.

**The noise-floor item closed the same day it was extended.** `injection` and `topic_scope`
were the two detectors named as never having a seed replicate; both ran two seeds on
2026-08-24 and came back inside their own floor, `topic_scope` needing a `--seed` override
added to `border_train.train_embed` first, since it had none. Every detector with a reported
retrain delta in this project now has a measured noise floor. See `reports/SEED_CONTROL.md`
in the training repository.

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

## The corpora, four measured gaps and one generation campaign, closed 2026-08-24

These were items 1, 2, 5 and 6 until 2026-08-18. They are one item because they are one cause:
a corpus that is thin in places and the wrong shape in others. Every part needs the generation
endpoint, so they queue rather than compete, and a single campaign addresses all four.

The four, ordered by what a caller would notice:

### `moderation` reads account access as intrusion, closed 2026-08-24

**Fired on 5 of 12 ordinary support questions**, at 0.90 to 0.98. Four account-access
questions read as `cyber_intrusion`, including "How do I reset my password?" at 0.97, and
"How do I report a suspicious message I received?" read as `sexual_exploitation` at 0.90.
That last one was a user trying to report abuse being labelled as the abuse.

Not a weak model. Mean per-language F1 0.9919 over 58 to 60 test examples per language,
positives 0.984 to 1.000 per label, and a false positive rate of 0.000 on all three mundane
registers. Every one of those was true and none covered account access, because the mundane
registers were informational, operational and transactional prose.

The fix had already landed in the corpus on 2026-08-19, a shared `mundane_account_access`
register plus a constraint stopping the mundane registers from writing phishing-lure surface
forms, both built for this exact failure and for the same one in `injection`. What had not
happened was a retrain: the corpus sat unused for five days, and a partial retrain
(`moderation-v4-s42`) existed on disk without its fp32 half, so nothing could be gated or
published from it. Retrained clean on 2026-08-24, INT8 flip gate at 0 of 300 decisions moved,
`tests/test_support_questions.py`'s strict xfail now XPASSes, and every per-label delta
against the previous model sits inside or above the seed-noise floor with no regressions.
Published as `flowxai/moderation` revision `29c283bd`, and `moderation` is now `enabled: true`
in both shipped policies.

The calibrated threshold moved with the retrain, 0.84 to 0.81, and is not being followed: the
validation curve is flat from 0.9288 at 0.50 to a peak of 0.9372 at 0.81, and three
calibration runs against this corpus (two seed replicates plus this retrain) read 0.69, 0.83
and 0.81. The shipped default stays at the reviewed 0.84, the same finding this project has
already made for `nsfw` and `politeness`.

- **Where**: `tests/test_support_questions.py`, `reports/moderation_v4_seed_control.json` in
  the training repository.

### The verification pass disagrees with itself in three different ways, closed 2026-08-24

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

**Both owner decisions this section asked for are settled, 2026-08-24.**
`docs/moderation-taxonomy-proposal.md` moves from "proposal, not decided" to accepted: the 13
labels are final, severity is deliberately deferred to the policy threshold,
`intellectual_property` stays out and `election_integrity` stays in, and the definition is
**facilitation, not content**, matching the doc's own framing: "does this facilitate, solicit
or promote serious harm", not what a text merely contains or mentions. That resolves the
question below in the opposite direction from this section's own earlier reasoning, which is
worth stating plainly rather than quietly overwriting.

**The checker almost never confirms `extremism`, and on a closer look it is expected
disagreement rather than a defect. This section first called it a generation bug needing
multi-labeling; that conclusion did not survive checking it against two things already true
of this project.** Per-label agreement, from `reports/moderation_verification.json`:

| label | agree | differ | agreement |
|---|---|---|---|
| `extremism` | 54 | 1,285 | **0.040** |
| `sexual_exploitation` | 547 | 790 | 0.409 |
| `violent_facilitation` | 733 | 619 | 0.542 |
| `election_integrity` | 1,194 | 158 | 0.883 |
| `defamation` | 1,249 | 103 | 0.924 |

Every one of the 1,201 `label_replaced` disagreements where the corpus said `extremism` was
generated single-label, and what the checker calls them instead is the concrete act the text
describes: `violent_facilitation` on 63.6%, `weapons_cbrn` on 31.2%, `property_crime` on 15.7%.
The taxonomy's own definition already covers this: "the text has to describe, seek or offer
help with violence, an attack, a weapon, a target, combat, sabotage, or training for those",
so operational content inside an extremism-register row is not a labelling mistake, it is the
definition being satisfied. Multi-labelling it against the verifier's read would also cross a
line this project already drew on purpose: `enrich_moderation.py` adds a label only when the
verifier *keeps* the generator's own label and adds to it, and refuses to act on a full
replacement, "a row for a person to read", precisely so a second model never becomes a
labeller by the back door. Every `extremism` case here is a replacement, not an addition, so
the existing rule already says not to touch it automatically. Left as documented, expected
disagreement rather than fixed: the generator is following its own definition, and building a
generator that self-reports multi-labels to close a gap this measured but did not show real
harm from is a larger change than the finding earns right now.

- **Where**: `reports/moderation_verify.gpt-oss-safeguard-20b.jsonl`,
  `data/moderation_taxonomy.yaml`'s `extremism` entry.
- **Not a fix**: extending `enrich_moderation.py`'s add-only rule to cover this case. That
  rule exists specifically to stop a verifier disagreement from becoming an automatic label
  change, and the `child_safety` near-miss it already records is why.

**`positive_called_empty`, 1,819 rows corpus-wide, closed 2026-08-24.** The report's 500-row
sample pointed at `election_integrity` and `defamation`; the full store told a different story:

| label | rows |
|---|---|
| `sexual_exploitation` | **762** |
| `violent_facilitation` | 190 |
| `self_harm` | 151 |
| `property_crime` | 149 |
| `hate_incitement` | 130 |
| `election_integrity` | 122 |
| `defamation` | 90 |
| `extremism` | 72 |
| `illicit_drugs` | 53 |
| `weapons_cbrn` | 42 |
| `cyber_intrusion` | 35 |
| `fraud_deception` | 23 |

`sexual_exploitation` alone was 762, five times `election_integrity` and 42 percent of the
total. Reading the actual rows found the cause: 367 of 762 and 64 of `self_harm`'s 151
justified themselves in the generator's own `why` field as help, protection or reporting,
"offers help for sexual exploitation" on an organisation offering trafficking victims free
shelter, "Ask for child trafficking protection" on a question about keeping children safe.
Both are the opposite of a positive, and the checker was correctly reading no hazard in them.

**Fixed in `_positive_spec()`, the prompt every one of the twelve labels is generated from,**
since the ambiguity ("asking for help or offering it" without saying which side of the harm)
was general even though `sexual_exploitation` and `self_harm` hit it hardest. The corpus was
regenerated whole, 30,469 examples, `prompt_version="moderation_solicitation_v5"`, at
~$12.81 on `claude-haiku-4-5`. A 60-row spot check against the local verifier across the five
worst-affected labels found the specific victim-support pattern gone entirely; an 18 percent
residual empty rate remained, but reading those rows found a different, smaller tail (vague
or truncated sentences, one plain verifier miss on an unambiguous case), not a recurrence.

Retrained, seed 42: flip gate 2 of 300 decisions moved, both within the 0.02 tolerance band.
`tests/test_support_questions.py` unaffected, still passing. Mean per-language F1 fell from
0.9925 to 0.9708 and every one of the twelve labels reads lower, which is the corpus losing
the easy, wrongly-labelled rows rather than a regression, the same trade `nsfw`'s retrain made
deliberately in the other direction once (0.976 to 0.918). Published as `flowxai/moderation`
revision `7df4570d`.

**The 183 rows the checker calls hazardous and the corpus calls benign are expected
disagreement under the accepted definition, not a corpus defect.** 74 of them sit in a
`mundane_*` register, the generator's own name for plainly benign prose, and 64 of those 74
are `fraud_deception`. The rows are phishing-shaped: a security-update pretext with a
same-day deadline and a `ResetPassword.it` lookalike domain, a utility notice closing with "to
avoid service interruption" and a phone number, a plaintext server-room password. Ordinary
transactional prose and a phishing lure share a surface form, so a register that asks for one
produces the other.

The generator says which rule it applied, in its own `why` field: `keine Hilfsanfrage`,
`nessuna richiesta di aiuto`, `pas de demande d'aide`, "not a request for help", on 1,934 of
6,227 mundane rows. That rule is close kin to the now-accepted "facilitates, solicits or
promotes": an ordinary transactional notice does none of the three regardless of its surface
resemblance to a lure, so the corpus is right to call it benign and the checker's disagreement
is it reading `fraud_deception`'s content-shaped definition in
`docs/moderation-taxonomy-proposal.md` ("scams, phishing, social engineering...") rather than
the facilitation test the taxonomy has now settled on. This section previously concluded the
opposite, that the 74 rows were corpus errors, reasoning from a content-based reading that the
2026-08-24 decision superseded. Corrected here rather than silently edited, in this project's
usual way of keeping a wrong conclusion visible next to what replaced it.

- **Where**: `uv run python -m border_train.read_disagreements --dump rows.json` in the
  training repo, which reads `reports/moderation_verify.gpt-oss-safeguard-20b.jsonl`.
- **Fix, if any**: `docs/moderation-taxonomy-proposal.md`'s per-label boundary prose could
  restate each definition in facilitation terms explicitly (`fraud_deception` in particular),
  so a future labeller or checker run against the same policy does not reintroduce this
  reading. Not a corpus regeneration: the 74 rows do not need to change. The `*_near_miss`
  half of the 183, 109 rows, is already expected behaviour for a register whose job is to sit
  near the boundary.

The verifier deliberately edits nothing, so the disagreement list is the artifact and reading
it is the work. The report's own `disagreements` list is a 500-row stratified sample, so its
shares are within that sample; the tables above are corpus totals from the full store.

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
0 of 300 decisions changed, and `nsfw` Maltese's seed spread down from 0.3294 to 0.1179.

**Adopted 2026-08-20.** Published as `flowxai/nsfw` revision `6c54edcd`, `flowxai/gibberish`
revision `9d71506e`, `flowxai/politeness` revision `63c3e6f1`, all three verified against the
library's own suite before and after. The calibrated thresholds are not adopted alongside the
quality gain: `nsfw` and `politeness` read 0.63/0.86 and 0.10/0.36 across the two seeds, both
from validation curves flat enough that calibration is picking the argmax of noise rather than
a real optimum, sweeping either `nsfw` seed's curve gives macro F1 0.8969 to 0.9190 from 0.50
to 0.95. The shipped policy keeps 0.76 and 0.89, reviewed by hand, unchanged by either retrain,
and both model cards and the site's own eval pages now carry the finding rather than presenting
the raw sweep result as tuned.

`politeness`'s published checkpoint is a re-run rather than the one `reports/THICK_CORPORA.md`
measured: seed 42's `model.safetensors` was found to be a 0-byte file on disk when preparing to
export it, retrained from the same corpus rather than recovered, gate clean at 0 of 300 on the
new export. Seed 1337's checkpoint is still on `border-l4-x`'s persistent disk and has not been
pulled down.

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

**`tests/test_groundedness_probes.py` failed against the real published weights on
2026-08-24, and the harness was wrong, not the model.** This machine had only ever tested
`groundedness` through the local override; running the suite against the actual fetched
weights for the first time found four failures, one of them 0.286 accuracy against a
0.500 chance baseline. The `scored` fixture compared `got == row["label"]` and `got in
UNGROUNDED = {"unsupported", "contradicted"}`, where `got` came from `max(judged, ...)`.
Correct for the three-way candidates this file was written against, but `judge()` on the
published binary artifact returns `{"grounded", "not_grounded"}`, so `got` could never
equal a three-way gold label and could never be a member of `UNGROUNDED` either. The
"exact" accuracy silently read 0.0 and "binary" accuracy silently read the fraction of
gold rows labelled `supported`, 12 of 42, which is why it landed under its own chance
line. `tests/test_t3.py` had already solved this exact problem with its `is_grounded`
helper, reading the decision through `_verdict`/`_reads_grounded` rather than the label
string; `test_groundedness_probes.py` was never updated to match when the binary artifact
was adopted. Fixed the same way. The corrected binary accuracy is 0.6905, matching the
"binary at 0.78 alone" figure already published in
`training/docs/groundedness-held-out-probes.md`, so the shipped model was never in
question. The exact-accuracy and per-shape tests now skip against a binary head rather
than fail, since a two-class head cannot express `unsupported` against `contradicted` by
construction.

One of the four failures was real and is the known weakness two paragraphs up, restated
with a live number: `tests/test_t3.py::test_a_claim_weaker_than_the_source_is_supported`
reads `not_grounded` at 0.8625 on the exact case the model card documents under "Known
weakness: it errs toward caution". Re-pinned as a strict xfail rather than left failing,
matching how the rest of this file already tracks a documented model limitation. Full
suite against the live published weights: 2109 passed, 21 skipped, 5 xfailed, zero
failures.

**Diagnosed 2026-08-24, not fixed, and narrowed twice in one sitting: the documented
"two-period source" reflex was never about periods, and it is not a general property of
short sources either.** Full progression in `training/docs/groundedness-held-out-probes.md`.
Re-tested against the live published weights with variables isolated one at a time: the
period contributes nothing, the qualifying clause contributes nothing, the sentence
boundary does, joining identical words into one sentence flips the verdict straight back.
That much held.

What did not hold was the scope. A five-domain, paraphrased-candidate, three-length set found
four of five domains read correctly at every length including bare, contradicting a general
"short sources are unreliable" claim. The flip reproduced perfectly on money, three
independent fee examples, all confidently right padded and confidently wrong bare. Crossing
magnitude against framing narrowed it again: a 12 million EUR fee is length-insensitive, a
non-fee balance at 5 EUR shows a weaker version of the gap, a non-monetary quantity at a
comparable magnitude shows none. Currency, not magnitude, is closer to the operative
variable, amplified by fee or charge framing specifically, and that is not yet a settled rule
either.

Recorded as three narrowings inside one sitting rather than a single clean mechanism,
deliberately, because a plausible explanation from a handful of examples is a hypothesis
until it survives a fact it was not built to explain, and this file has now made that mistake
about groundedness enough times to name it as the pattern rather than the exception. Not a
fix. Two paths still untried, and neither is worth acting on until a real many-fact,
many-currency, many-language diagnostic set exists rather than the roughly twenty `judge()`
calls run so far: a length-balanced corpus slice, the same fix already adopted for `nsfw`,
`toxicity` and `bias` against their own length confounds, or a library-side length floor
reporting `groundedness_source_too_short` rather than guessing. No GPU spend, no generation
endpoint used for any of it.

**Paused here 2026-08-24. Next steps, none started:**

1. Build `border_train.groundedness_length_ablation` as a real module rather than ad-hoc
   `judge()` calls in a shell: currencies beyond EUR, magnitudes spanning single digits to
   millions, fee/charge framing crossed against plain-statement framing, and at least two
   more languages so this is not another English-only finding. Target something like 200
   to 300 pairs, enough to report a rate rather than a handful of anecdotes.
2. Only after that set exists, decide between the two paths above on its numbers, not on
   the roughly twenty calls run today. Whichever is chosen, re-run the 42 hand-written
   probes and the notation ablation afterward, since both already touch money amounts and
   either fix could move them without anyone having asked it to.
3. If the rate turns out to be low and confined to small currency amounts specifically,
   a library-side length floor is the cheaper and lower-risk of the two and should be
   tried first: it needs no retrain and no generation spend.

## No retrain delta in this project has a measured noise floor, closed 2026-08-24

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

**`bias` and `toxicity` were seed-controlled on 2026-08-24, the two of the original three still
missing one. Both are inside their own floor against the model that actually ships.**

    bias        per-label floor      mean spread 0.0059, max 0.0124
                per-language floor   mean spread 0.0066, max 0.0256, 0 of 26 over 0.10
                calibrated threshold 0.89, 0.95, against a shipped default of 0.5
    toxicity    per-label floor      mean spread 0.0049, max 0.0114
                per-language floor   mean spread 0.0065, max 0.0454, 0 of 26 over 0.10
                calibrated threshold 0.46, 0.54, against a shipped default of 0.5

Every label in both detectors reads `inside the floor`. Neither calibrated pair brackets
usefully either, which is the same flat-curve finding `configs/bias.yaml` and
`configs/toxicity.yaml` already state as the reason 0.5 ships instead of the calibrated value:
two more seeds, two more thresholds nowhere near each other or the default, which is what a
flat validation curve predicts rather than a new finding.

The `+0.0206` this item asked about turned out to be the wrong question to re-ask, and finding
that out is the part worth recording. `bias` was retrained again on 2026-08-17, nine times the
corpus, closing part of item 1 above, so the model that claim was about has not shipped since
that date. `border-train-l4`'s own disk still carried the pre-2026-08-17 artifact under the
name `artifacts/bias-full`, and running `compare_runs --against` that directory first, before
noticing the date, produced exactly the shape a real effect would: one label at +0.0609, a
plausible-looking win. It was the corpus change arriving twice in one comparison, once as the
real 2026-08-17 retrain and once again as the stale directory standing in for the thing it
replaced. Re-run against `artifacts_local/bias-full/bias_eval.json`, the artifact actually
published, and every label moved inside the floor. Same lesson as `nsfw-full-preretrain`
carrying the higher score under the older name: **read the report the baseline came from, not
the directory it happened to be sitting in.**

`toxicity`'s own baseline needed no such correction: its corpus has been stable since
2026-08-14, the day the shipped model was trained on it, so `artifacts/toxicity-full` and
`artifacts_local/toxicity-full` describe the same run.

This closed the three the 2026-08-14 table named. It did not close the item's title as a
general claim at the time: `injection` and `topic_scope` had never had a seed replicate, and
`injection`'s reported deltas were pass rates on a fixed probe set rather than a
per-language F1 comparison, which read as needing an adapted procedure rather than the one
already in hand.

**Both closed the same day.** `injection`'s own trainer already writes a standard
per-language eval report regardless of how its retrain deltas have historically been read, so
`compare_runs` needed no adaptation:

| | |
|---|---|
| per-label spread, mean / max | 0.0032 / 0.0070 |
| per-language spread, mean / max | 0.0082 / 0.0455 |
| languages over 0.10 spread | 0 of 26 |
| calibrated threshold, two seeds | 0.02, 0.02 |
| verdict | every label inside the floor |

`injection`'s calibrated threshold is stable across seeds, unlike every other detector in
this section, and the shipped policy default sits far above it (0.35 to 0.43) by deliberate
choice: a missed injection costs more than a review, not because calibration was noisy.

`topic_scope` trains through `border_train.train_embed`, which had neither a `--seed`
override nor a `run.json`; both were added, matching `train.py`'s mechanism. Its report has
no `per_label` block, so the comparison is `top1_accuracy` and the per-node breakdown
directly, in `reports/topic_scope_seed_control.json`:

| | |
|---|---|
| top1_accuracy, two seeds | 0.8391, 0.8478 |
| top1_accuracy, shipped | 0.8571 |
| per-node spread, mean / max | 0.0543 / 0.2222 |
| widest node | `insurance/claims/home`, 0.7778 and 1.0000 |

The aggregate is stable. The per-node figures are not, on a corpus of 15 nodes and roughly
five test examples each, the same shape as `nsfw`'s Maltese cell on 9 to 10 positives: a
per-node score at this size is a property of the draw, not a per-node quality claim.

Every detector with a reported retrain delta in this project now has a measured noise floor.

- **Where**: `reports/bias_seed_control.json`, `reports/toxicity_seed_control.json`,
  `reports/injection_seed_control.json`, `reports/topic_scope_seed_control.json`,
  `reports/SEED_CONTROL.md`.

## Closed while writing this

**Every published model now keeps both halves, fp32 and quantised, and the count of four
missing is zero.** Re-checking a quantised export needs both, and four of eleven published
models were missing their fp32 half as of 2026-08-18: `nsfw`, `toxicity`, `regulated_advice`
and `injection` were recovered from a VM that still existed; `gibberish`, `politeness`,
`moderation` and `topic_scope` were not, trained on a VM that no longer does.

Closed in three steps rather than one. `moderation` and `gibberish` closed themselves on
2026-08-19 and 2026-08-20: both retrains, adopted for the corpus-thickening item, wrote
`model.safetensors` alongside the int8 export by default, so nothing had to be recovered.
`politeness` needed one more step: its own retrain's seed 42 checkpoint turned out to be a
0-byte file on disk mid-export, so it was retrained rather than recovered, and seed 1337's
checkpoint, the one `reports/THICK_CORPORA.md` actually measured, sat on `border-l4-x`'s
stopped-not-deleted disk until it was pulled down on 2026-08-24, closing the last gap.
`topic_scope` needed nothing: it is unconfigured in both shipped policies and T3, so its
missing fp32 half cannot affect a caller, and its manifest already records the fullest
verification of the set, cosine-to-torch for both halves and an int8 export that moved 2 of
200 top-1 taxonomy nodes.

- **Where**: `artifacts_local/<detector>-full/model.safetensors` for all eleven, and
  `artifacts_local/politeness-v4-s1337` for the seed the shipped model is not, kept as a
  replicate rather than discarded.
- **The habit that closes this permanently**: a training run writes `model.safetensors` and
  `run.json` at the artifact root by default, so keeping both halves is a retention habit
  from here rather than a recovery exercise each time.


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
