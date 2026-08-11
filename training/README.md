# Training the moderation model

A multi-label hazard classifier on a Qwen3-0.6B base, replacing the capability that
`llamaguard_7b` and `shieldgemma_2b` provide without their weights, neither of which is
Apache-2.0 compatible.

**Nothing in this directory ships.** `pyproject.toml` packages `src/flowx_border` only,
so the wheel does not contain it and the training dependencies are not runtime
dependencies. Read that as the rule it is: nothing here may be imported by the library.

## Why a classification head rather than a generative model

Llama Guard and ShieldGemma are classifiers wearing generative clothing. Both emit
`safe` or `unsafe` plus the categories that fired, and generating that token by token
costs roughly twenty sequential forward passes to answer a question one pass answers.

Two consequences follow, and both are why this design was chosen on 2026-08-11:

- **Latency.** A generative 1.7B on CPU is seconds. A 0.6B classification head is
  around 110 ms at the reference input, which fits a T2 budget and keeps the detector
  in `CORE`, so a deployment needs no accelerator.
- **Determinism.** A generative verdict is only reproducible with decoding pinned, and
  an evidence record that cannot be reproduced is a log line with a signature on it. A
  single forward pass has nothing to pin.

The cost, stated because it is real: the other seven classifiers in this library are
XLM-RoBERTa base, so a Qwen3-0.6B moderation model is a second architecture to load
rather than a session shared with them.

## The pipeline

    prepare_data.py   build the training set, write train/dev/test as JSONL
    train.py          fine-tune the head, and the base with LoRA
    evaluate.py       the per-language table CLAUDE.md requires
    export_onnx.py    ONNX plus INT8, the form the library loads

Run them in that order. Every one takes `--config config.yaml`.

## Data is the long pole, and it is not solved here

The pipeline is complete; the corpus is not. What exists is a seed set, and it is a seed
set rather than a training set. Two honest statements about it:

**It is mostly English.** Qwen3 is multilingual and cross-lingual transfer from English
supervision is real, but "real" is not a number. Whether it holds for Maltese is an
empirical question, which is why `evaluate.py` produces a row per language rather than
an aggregate, and why a language with no training data is expected to show a low number
rather than to disappear into an average.

**Publish the bad rows.** CLAUDE.md is explicit: where a language underperforms, publish
the number and say so, do not drop the language from the table. A model card that shows
26 rows with 9 good ones is worth more than one that shows a single macro-average.

## Running it on the L4

`provision.sh` creates the instance, installs the dependencies and copies this
directory. It is deliberately a script you can read rather than a Terraform module: it
creates one VM, and the thing you most need to be able to check is that it is the VM you
expected and it is deleted afterwards.

    ./provision.sh create      # create the instance and install
    ./provision.sh run         # start training under nohup, returns immediately
    ./provision.sh logs        # tail the training log
    ./provision.sh fetch       # copy artifacts back
    ./provision.sh delete      # destroy the instance

The instance is not preemptible by default. A preempted run at hour six of eight is a
worse outcome than the cost difference, and `--preemptible` is there for when it is not.
