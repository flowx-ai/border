# Brief: port the Guardrails Hub validators

You are picking up one scoped piece of the `flowx-border` project while another session
works in parallel on the model pipeline and the library core. This file is your starting
context. Read `CLAUDE.md` fully before writing anything: it is the project authority and it
overrides this file wherever they disagree.

## The job in one paragraph

Take the validator set from [guardrails-ai/guardrails-hub-monorepo](https://github.com/guardrails-ai/guardrails-hub-monorepo),
work out which of them are worth having, and port those so they work across the 26
languages this project supports rather than English only. The owner's phrasing was "i want
them too but improved for all languages". The improvement *is* the multilingual part; a
port that only works in English is not worth doing, because English-only is what the
originals already are.

## Read these first, in this order

1. `CLAUDE.md`, all of it. Especially constraints 1 to 7, the language coverage section, the
   writing style section, and the compliance language section.
2. `BUILD_PLAN.md` for how the project is sequenced.
3. `src/flowx_border/detectors/secrets.py` and `disclosure.py`. These are the two existing
   rule-based detectors and they are the closest model for what you are writing. Note how
   `disclosure.py` keeps its language data in `data/disclosure_phrasings.yaml` rather than in
   Python, and how each file explains what it refuses to fire on and why.
4. `src/flowx_border/policy.py` to see how configuration is expressed as data.

## The constraint that will bite you

**CLAUDE.md constraint 3 fixes the detector set at thirteen, and says a fourteenth needs an
explicit instruction from the owner.** Most validators look like they want to be new
detectors. They may not become one without asking.

So the first real decision is where a port lands, and you should raise it rather than
choose silently. The options, as they look from here:

- **A separate `validators` module** that a caller composes itself, outside the tier engine
  and outside the catalogue. Nothing to approve, no detector count changes, but it does not
  get an evidence record or a tier, which is most of what this library is for.
- **Policy-level configuration of existing detectors.** A competitor wordlist becomes
  options on `topic_scope`; a substring list becomes options on an existing rule detector.
  Fits the architecture, costs no new detectors, and only works for validators that really
  are a variation on something already present.
- **New detectors, with the owner's explicit instruction.** The honest route for anything
  genuinely new. Ask for it by name, with the list, rather than adding thirteen entries and
  explaining afterwards.

There is prior art for asking: the set went from eight to thirteen on 2026-08-10 because the
owner lifted the limit in writing, twice. The record of that reasoning is in constraint 3,
including the tradeoff it made. Read it before proposing a fourteenth.

## What is already known about the validator set

From an earlier pass, so verify rather than trust:

- Roughly 20 validators are language-independent rules. Regex shapes, format checks,
  structural things. These are the cheap wins.
- Roughly 9 are wordlist-driven. These are the ones where "improved for all languages"
  means real work: a wordlist is 26 wordlists, and a wordlist you cannot read is a wordlist
  you cannot review. Follow the `disclosure_phrasings.yaml` pattern, including its
  `reviewed: false` honesty field, because you will not have native speakers either.
- Roughly 21 are not portable. Some need a hosted model, which constraint 4 forbids inside a
  detector. Some need a network call at scan time, which constraint 1 forbids. Some are not
  security checks at all. **Document every one of these by name with the reason.** There is
  an existing example of exactly this shape in
  `src/flowx_border/adapters/llm_guard_compat.py`, whose `UNSUPPORTED` table names all 14
  llm-guard scanners it will not pretend to implement, and `docs/migrating-from-llm-guard.md`
  generates its table from that code so the two cannot drift.

## Licences

Checked earlier and worth re-checking: 64 of 65 validators are MIT, so attribution
suffices. The licence risk is not the validator code, it is **model weights**: Llama Guard,
ShieldGemma, and some GLiNER variants are not Apache-2.0 compatible, and some are
cc-by-nc. This project is Apache-2.0 and every source file carries the SPDX header. If a
validator's value is entirely in a non-commercial model, porting the code without the model
is not a port, and you should say so rather than ship a shell.

## Boundaries: files another session is actively editing

Do not edit these. Another session is committing to them right now and you will conflict:

    src/flowx_border/registry.py
    src/flowx_border/detectors/catalogue.py
    src/flowx_border/detectors/{pii,output_leakage,classifier,secrets,disclosure}.py
    src/flowx_border/models/
    src/flowx_border/adapters/
    src/flowx_border/policy.py
    src/flowx_border/engine.py
    pyproject.toml
    CLAUDE.md

Work in new files. If your design needs a change to `catalogue.py` or `registry.py`, that is
the signal to stop and coordinate, not to make the edit.

Suggested home for new work, subject to the design decision above:

    src/flowx_border/validators/          new package
    tests/test_validators.py
    docs/porting-guardrails-validators.md the by-name table, including the unsupported list

## How this project expects work to be done

These are not stylistic preferences, they are the rules the existing code follows:

- **Tests first.** Write the failing test, then the implementation. `pytest -q` must pass
  with no network: `tests/conftest.py` blocks outbound connections for the whole suite.
- **Fixtures cover all 26 languages.** English-only fixtures are called a bug in CLAUDE.md.
  There is a worked example in `tests/test_disclosure.py`, which carries a disclosed and an
  undisclosed sentence for each of the 26.
- **No silent no-ops, ever.** This is the project's strongest theme. A check that cannot run
  must raise or must record that it could not, never return "nothing found". Several bugs
  found today were exactly this shape: a tokenizer that silently truncated long documents, a
  metric that reported F1 1.000 for a model that was 84 percent accurate, four detectors
  whose validation split contained no positive examples.
- **`ruff check`, `ruff format --check` and `mypy --strict src` must be clean.** Line length
  88.
- **No em-dashes** anywhere, including commit messages. Check with the `printf` recipe in
  CLAUDE.md's commands section.
- **Claims must be checkable.** If a number appears in a doc, a benchmark in the repo has to
  produce it.
- **The repository will be made public.** Write every comment and commit message as though a
  stranger will read it, because one will.

## Commands

```sh
uv sync
uv run pytest -q
uv run ruff check . && uv run ruff format --check .
uv run mypy --strict src
```

## What good output looks like

1. A short written proposal, before implementing: which validators you are porting, into
   which of the three shapes above, and which you are declining with the reason. Wait for the
   owner on anything that needs a fourteenth detector.
2. The ported validators, with per-language data in YAML and `reviewed:` honesty flags where
   you could not verify a language.
3. `docs/porting-guardrails-validators.md` naming every validator in the hub, ported or not,
   generated from the code so it cannot drift.
4. Tests covering 26 languages, passing offline, with the suite green and the linters clean.

## One thing worth knowing about the tone here

Every file in this repository explains why it is the way it is, especially where a decision
looks odd. `secrets.py` documents the five shapes it refuses to fire on and that a false
positive there is a refused request a user cannot work around. `output_leakage.py` explains
why it reports `leakage_unverifiable` instead of nothing. Match that. A comment that says
what the code does is noise; a comment that says what would go wrong otherwise is the point.
