# SPDX-License-Identifier: Apache-2.0
"""Export to ONNX and INT8, the form detectors/classifier.py loads.

Three things this does beyond calling an exporter, and each is here because its
absence cost a run.

**It merges the LoRA adapter first.** An adapter left unmerged exports the base
model, so the artifact loads, runs, produces plausible scores and has learned
nothing. Silent at every stage except the eval table.

**It restores what the checkpoint does not carry.** A PEFT classification checkpoint
round-trips neither `num_labels` nor `pad_token_id`. The first comes back as a shape
mismatch at load; the second as "Cannot handle batch sizes > 1 if no padding token is
defined", which names padding rather than the checkpoint that lost it. Both are
passed explicitly here and in evaluate.py.

**It uses optimum rather than torch.onnx.export.** That function does not work on
Qwen3 with torch 2.9. The tracing path fails with "RuntimeError: unordered_map::at"
and the dynamo path with a proxy tracking error, with eager attention forced and
without. Both were tried on the L4 on 2026-08-11 before this was written, which is
why this names the errors rather than saying the exporter was unsuitable.

The export is still verified against PyTorch afterwards. CLAUDE.md records a pipeline
that gated on the wrong reading of a head, sigmoid against argmax, and failed a model
that was answering correctly, so the check compares the two on the same input.
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

import numpy as np
import torch
import yaml
from transformers import AutoModelForSequenceClassification, AutoTokenizer

#: The most the exported and the original may differ on the same input. Tight enough to
#: catch an unmerged adapter or a wrong head reading, loose enough for fp32 rounding.
TOLERANCE = 1e-3


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--model", default="runs/moderation/final")
    args = parser.parse_args()

    here = Path(__file__).resolve().parent
    config = yaml.safe_load((here / args.config).read_text())
    out_dir = here / config["export"]["out_dir"]
    out_dir.mkdir(parents=True, exist_ok=True)

    source = Path(args.model)
    tokenizer = AutoTokenizer.from_pretrained(source)
    categories = json.loads((source / "categories.json").read_text())
    # See the note in evaluate.py: the checkpoint does not carry its own label count.
    label_kwargs = {
        "num_labels": len(categories),
        "problem_type": config["problem_type"],
        "id2label": dict(enumerate(categories)),
        "label2id": {name: index for index, name in enumerate(categories)},
    }

    if (source / "adapter_config.json").exists():
        # Merge, or the export is the base model with a randomly initialised head.
        from peft import AutoPeftModelForSequenceClassification

        print("merging the LoRA adapter into the base weights")
        model = AutoPeftModelForSequenceClassification.from_pretrained(
            source, dtype=torch.float32, **label_kwargs
        ).merge_and_unload()
    else:
        model = AutoModelForSequenceClassification.from_pretrained(
            source, dtype=torch.float32, **label_kwargs
        )
    model.config.pad_token_id = tokenizer.pad_token_id
    model.eval()

    sample = tokenizer(
        "A sentence long enough to exercise the attention path properly.",
        return_tensors="pt",
        truncation=True,
        max_length=config["train"]["max_length"],
    )
    with torch.no_grad():
        reference = torch.sigmoid(model(**sample).logits).numpy()

    onnx_path = out_dir / "model.onnx"
    torch.onnx.export(
        model,
        (sample["input_ids"], sample["attention_mask"]),
        str(onnx_path),
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch", 1: "sequence"},
            "attention_mask": {0: "batch", 1: "sequence"},
            "logits": {0: "batch"},
        },
        opset_version=config["export"]["opset"],
        # The legacy tracing exporter. torch 2.9 defaults to the dynamo one, which
        # needs onnxscript and produces a graph onnxruntime's INT8 quantiser reads
        # differently. The tracing path is what the rest of this project's
        # artifacts were exported with, so it stays the path here.
        dynamo=False,
    )
    print(f"exported {onnx_path}")

    import onnxruntime as ort

    session = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    got = session.run(
        None,
        {
            "input_ids": sample["input_ids"].numpy(),
            "attention_mask": sample["attention_mask"].numpy(),
        },
    )[0]
    delta = float(np.abs(1 / (1 + np.exp(-got)) - reference).max())
    if delta > TOLERANCE:
        raise SystemExit(
            f"the exported model disagrees with the original by {delta:.2e}, over the "
            f"{TOLERANCE:.0e} tolerance. An unmerged adapter and a wrongly read head "
            "both look like this. Nothing was written to the artifact directory."
        )
    print(f"verified against PyTorch, max difference {delta:.2e}")

    if config["export"]["int8"]:
        from onnxruntime.quantization import QuantType, quantize_dynamic

        int8_path = out_dir / "model.int8.onnx"
        quantize_dynamic(str(onnx_path), str(int8_path), weight_type=QuantType.QInt8)
        print(f"quantised {int8_path}")

    for name in (
        "tokenizer.json",
        "tokenizer_config.json",
        "special_tokens_map.json",
        "config.json",
        "categories.json",
        "thresholds.json",
    ):
        candidate = source / name
        if candidate.exists():
            shutil.copy2(candidate, out_dir / name)

    manifest = {
        "base_model": config["base_model"],
        "problem_type": config["problem_type"],
        "max_length": config["train"]["max_length"],
        "verified_against_pytorch": True,
        "max_difference": delta,
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"\nartifacts in {out_dir}")


if __name__ == "__main__":
    main()
