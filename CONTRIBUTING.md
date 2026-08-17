# Contributing

Thanks for looking. This file is the short version of how the library is built and what a
change has to satisfy. Most of it exists because something went wrong once.

## Do not put real personal data in an issue or a pull request

This is a library for finding personal data, so a bug report about it naturally wants to
quote the text that went wrong. Please do not. Use a synthetic equivalent with the same
shape: the same entity types, the same language, the same layout. If the shape is what
matters, the shape is what to send.

The tests are full of examples to copy. `tests/test_pii.py` and `tests/test_secrets.py`
use invented names and vendor-documented example credentials for exactly this reason.

## Setup

```sh
uv sync                     # includes the dev group
uv run pytest -q            # the default suite, passes with no network
uv run ruff check . && uv run ruff format --check .
uv run mypy --strict src
```

Python 3.11 or newer. Always go through `uv run`, since the host interpreter is usually
something else.

Two test markers:

- `slow` needs real model weights or measures latency. It is not excluded from the
  default run: it skips when the weights are not present, so a clone with no model cache
  reports skips rather than failures.
- `network` genuinely needs a socket. `tests/conftest.py` patches `socket.socket` to raise
  for everything else, which is how "a scan works with the interface down" stays true.

## What a change has to satisfy

**Tests first.** Write the failing test, then the implementation.

**A detector works in all 26 languages or it is not finished.** English plus five is a
bug. See `docs/reference/languages.md` for the list.

**Never mock an ONNX session.** If a detector test is too slow for the default run, mark
it `slow`. A mocked session tests the mock.

**A detector never silently does nothing.** Unconfigured, unavailable and uncomparable are
findings it reports, not conditions it passes through. A detector that returns no findings
because it could not run is indistinguishable from a clean scan, and in a security library
that is a vulnerability rather than a rough edge.

**Policy is data, never code.** A Python callback in a policy file would make
`policy_hash` a weaker claim than it looks, and it would stop a non-programmer reviewing a
policy.

**A scan is deterministic.** No sampling, no temperature, no clock inside a scan. An
evidence record exists to be checked later by somebody who was not there.

**The public API is two functions plus the loader.** `scan_input`, `scan_output`,
`load_policy`. A third public entry point is a product decision, so please open an issue
before writing one.

## Things that need their own commit

**A latency budget change**, with the measurement in the commit message. Never in the same
commit as the code that missed the budget. Budgets live in
`src/flowx_border/detectors/catalogue.py` and are asserted in `tests/test_budgets.py`
against the reference input recorded there.

**A change to `Decision` or `EvidenceRecord`.** Both are breaking, and every archived
record ever produced is downstream of them.

## Generated files

Some files are rendered from the code and a hand edit will be reverted by the next
regeneration, or will fail a test that compares the two:

| file | regenerate with |
|---|---|
| `docs/detectors.md` | `uv run python -m flowx_border.detectors.reference` |
| `docs/porting-guardrails-validators.md` | rendered from `detectors/guardrails_hub.py` |
| `docs/reference/performance.json` and `.md` | `uv run python benchmarks/collect.py --artifacts <dir>` |

If a number appears in prose anywhere, there has to be something in the repo that
produces it. A figure with no benchmark behind it is the thing this project is most
careful about, because it has published a stale one before.

## Style

Every source file carries the SPDX header `# SPDX-License-Identifier: Apache-2.0`. CI
checks it.

No em-dashes, in code, comments, documentation or commit messages. Use a comma, a colon,
parentheses or a full stop. CI greps for the character.

Sentence case for headings. No marketing language.

Conventional commits, and write the commit message for somebody trying to understand why
the code is shaped this way, not what the diff already shows.

## Compliance language

This library does not make anyone compliant with anything. It produces evidence about
controls that were applied, and the distinction is legally material rather than a
preference.

So please do not write, in documentation or in a docstring, that it is "AI Act compliant",
that it "ensures compliance", or that it "guarantees" or "certifies" anything. Obligations
under any AI regulation sit with the provider or deployer of a system, not with a library
inside it. `tests/test_readme.py` checks the README for this and nothing checks the rest,
so it is on the reviewer.

Phrasing that is accurate: it produces an auditable record of which checks ran and what
they found, it detects whether a required disclosure is present in output, and it supports
the evidence requirements of your own governance process.

## Adding a detector

There is no cap on how many detectors exist, and three things a new one has to do:

1. Work in all 26 languages, with fixtures for each. If it is model-backed, report a
   per-language evaluation rather than one aggregate, because an aggregate hides the tail
   and the tail is the point.
2. Meet its tier's budget at the reference input, asserted in `tests/test_budgets.py`.
3. Never silently do nothing, as above.

Declare whatever it needs beyond a CPU and the base install in `Spec.requires` in
`detectors/catalogue.py`: `network`, `gpu`, `llm` or `dependency`. A caller finds out what
they are taking on when they enable it, rather than from a latency graph in production.

If a change tempts you to branch on `detector.id` inside `engine.py`, the abstraction is
wrong. Please open an issue rather than adding the branch.
