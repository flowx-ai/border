# Session handoff: the Guardrails Hub validator port

Written 2026-08-11 at the end of the session that ran `GUARDRAILS_PORT.md`. This file is
for whoever picks the work up, including the parallel session it overlapped with.

**Delete this file before the repository goes public.** It is process, not product, and
CLAUDE.md is explicit that everything in here will be read by strangers.

## Where things stand

Seven pull requests merged. `main` was at `9323e15` when this was written.

    25 detectors catalogued, 15 built, 22 in CORE
    31 of the 65 Guardrails Hub validators ported into 9 detectors
    25 more answered by detectors that already existed
    9 not built, and none of them for want of effort

CI is green. It had been red since before this session for three unrelated reasons, all
now fixed: weight-dependent tests failing rather than skipping, the formatter reflowing
markdown, and an out-of-date image family in the training provisioner.

## What landed

Nine detectors, all rules, all with fixtures in 26 languages:

    banned_terms           six hub validators that were one mechanism with different
                           lists baked in. No wordlist ships, in any language.
    system_prompt_leakage  rewritten from whole-string similarity to containment
    markup_injection       rewritten from bleach.clean(x) != x
    internal_domains       host boundaries on both sides, punycode and Unicode
    output_format          sixteen shape validators collapsed into policy options
    postal_code            29 countries, shape plus published range rules
    repetition             sentence similarity, no dependencies
    sql_injection          sqlglot parse tree, first detector outside CORE
    url_reachability       first detector that leaves the machine
    invisible_text         T0, closes the InvisibleText gap the llm-guard doc named

Plus `detectors/multilingual.py`, which is where the 26-language behaviour lives and
which four of the above share, and `training/`, a moderation-model pipeline validated
end to end on an L4.

## Things that will bite the next person

**The parallel session's files were edited.** `GUARDRAILS_PORT.md` reserved them and the
constraint that made that necessary was lifted mid-session, so `catalogue.py`,
`registry.py`, `models/registry.py`, `CLAUDE.md`, `pyproject.toml`, `test_offline.py`,
`test_budgets.py` and `test_adapters.py` all changed here. Everything merged cleanly, but
**anything uncommitted in those files at the time will conflict.** `catalogue.py` is the
likely collision: it gained ten entries.

**A PEFT classification checkpoint does not round-trip its own config.** Neither
`num_labels` nor `pad_token_id` survives `save_model`. The first returns as a shape
mismatch at load, the second much later as "Cannot handle batch sizes > 1 if no padding
token is defined", which names padding rather than the checkpoint that lost it. Both are
passed explicitly in `training/evaluate.py` and `training/export_onnx.py`.

**`torch.onnx.export` does not work on Qwen3 with torch 2.9.** Tracing dies with
`RuntimeError: unordered_map::at`, dynamo with a proxy tracking error, with eager
attention forced and without. `optimum-onnx` handles it.

**Blunt line-wrapping scripts corrupted three files during this session.** Splitting a
long line without parsing it breaks f-strings and string literals, and the damage is
silent until the file is imported. `tests/test_repetition.py` had to be rewritten from
scratch. Wrap by hand or by generating the file, never by regex over arbitrary lines.

**Test fixtures can pass while proving nothing.** Two examples worth internalising: a
"broken postcode" made by replacing digits is still valid for a country whose rule is
shape only, and the Greek question mark U+037E is visually identical to a semicolon, so
a fixture meant to test it tested the wrong character. Both passed. Both were found by
adding a companion assertion that the *unbroken* case is clean.

## The publish attempt, and why it stopped

The owner asked to publish the six held-back models. Do not repeat the first two steps.

**Only three of seven staged models have weights.** In
`~/Dev/assay/training/publish_staging`, `toxicity`, `nsfw` and `bias` carry
`onnx/model.int8.onnx` at roughly 527 MB. `gibberish`, `injection`, `politeness` and
`regulatedadvice` are 16 MB: a card, a tokenizer, calibration and eval, and an `onnx/`
directory containing only `export_manifest.json`. Publishing those four would upload a
licence, a model card and per-language eval tables with no model behind them, which is
the silent no-op this project refuses everywhere else. `topic_scope` is not staged at
all. Their ONNX exports are presumably on `border-train`.

The three complete ones were verified: sha256 of each `model.int8.onnx` matches its
`export_manifest.json`, cards carry `license: apache-2.0` in the metadata, and the
per-language tables are present. They are ready. Nothing was uploaded and no repository
was created.

**Authentication is the immediate blocker.** The owner pasted a write token into the
chat, was told to revoke it, and did. That token turned out to be the same one cached at
`~/.cache/huggingface/token`, so revoking it left no working credential:
`hf auth login --force` is needed before any upload. Do not accept a token pasted into a
conversation; ask for `hf auth login` to be run directly instead.

**Publishing is not just uploading.** `models/registry.py` pins each model by repo,
revision and sha256, and only `piiguard` has a full `ModelSpec` today. Each published
model needs an entry with the sha of the uploaded file, which can only be computed after
upload. Upload, then compute, then wire, and only then does the detector count move.

## Costs left running

**`border-train`, a T4 in `us-east1-c` of `prj-ai-flowx-dev`, is RUNNING.** It is the
parallel session's box and was not touched here. It bills whether or not it is training.

The L4 created for the moderation run, `border-moderation-train` in `europe-west1-b`, was
deleted. `training/provision.sh create` recreates it.

## What is actually blocked, and by what

    moderation      a corpus. The pipeline runs; 1240 templated English rows produced
                    macro F1 0.472 on English and no data in 25 languages. That is a
                    pipeline validation, not a model.
    groundedness    a harder corpus. It scores 1.000, which its own registry note calls
                    saturated rather than good.
    injection       an ONNX export. Trained at macro F1 0.889.
    regulated_advice an ONNX export and threshold calibration. Trained at 0.983.
    six others      nothing. toxicity, nsfw, bias, gibberish, politeness and topic_scope
                    are trained and verified and held back by a release decision.

The single highest-value action is publishing, because it is a decision rather than
work. The highest-value engineering task is `pii`'s language coverage: it is trained on
9 of the 26 and `output_leakage` inherits that, so the gap is in a detector people
already rely on rather than one they do not have. CLAUDE.md lists what each missing
locale needs and it is a data task, not research.

## Still open, not blocked

    extracted_summary_sentences_match  the last hub validator buildable with no model.
                                       Containment, which system_prompt_leakage has.
    the taxonomy overlap               four of moderation's thirteen categories overlap
                                       toxicity, nsfw, bias and regulated_advice, none
                                       of which is built. One model could replace four.
                                       Decide before training again.
    CLAUDE.md "Current state"          still says the engine and every detector do not
                                       exist. It is the first thing the file tells a
                                       reader to read.
    reviewed: false                    26/26 disclosure phrasings, 26/26 system prompt
                                       phrasings, 29/29 postcode formats. Needs native
                                       speakers, not engineering.

## Two judgement calls worth revisiting

**Markdown is excluded from the formatter** (`[tool.ruff.format] exclude`). The
alternative was reformatting three files the parallel session wrote, removing alignment
they chose deliberately in a Literal table. One-line revert if the project would rather
the docs were formatted.

**`valid_address` is declined in its vendor half and built in its local half.** The
postcode check is `postal_code`; sending customer addresses to Google is not something a
library whose `pii` detector exists to stop personal data leaving should do. If that is
wanted, the vendor relationship already exists in the caller's code.
