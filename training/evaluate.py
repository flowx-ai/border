# SPDX-License-Identifier: Apache-2.0
"""The per-language table, and the per-category threshold search.

A model-backed detector has to report per-language numbers rather than
one
aggregate, and gives the reason plainly: an aggregate hides the tail, and the tail is
the
whole point of the project. So this prints a row per language including the ones with no
test data, where it prints the absence rather than omitting the row. A language missing
from a table reads as an oversight; a language showing "no data" reads as what it is.

The threshold search is the other half. Four detectors in this project reported
F1 0.000 in all 26 languages because their thresholds sat at 0.5 while their scores
separated positives from negatives well below it. A threshold left at a plausible
default
is how a detector becomes a no-op that still produces evidence records. So it is chosen
per category on the dev split and written out for the policy to carry.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np
import torch
import yaml
from transformers import AutoModelForSequenceClassification, AutoTokenizer

#: A PEFT classification checkpoint does not round-trip its label count.
#:
#: `trainer.save_model` on a LoRA-wrapped classifier writes the adapter and an
#: adapter_config pointing at the base repo, and the base repo's config has no
#: `num_labels`. So reloading rebuilds the head with the default 2 while the saved
#: weights have 13, and the failure arrives as a shape mismatch at load time:
#:
#:   size mismatch for score.modules_to_save.default.weight
#:   copying a param with shape [13, 1024], current model has [2, 1024]
#:
#: The count is therefore passed explicitly on every load, read from the categories the
#: model was trained against rather than from the checkpoint that does not carry it.


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def score_all(
    model: Any, tokenizer: Any, rows: list[dict[str, Any]], length: int
) -> Any:
    out = []
    model.eval()
    with torch.no_grad():
        for start in range(0, len(rows), 32):
            batch = rows[start : start + 32]
            encoded = tokenizer(
                [row["text"] for row in batch],
                truncation=True,
                max_length=length,
                padding=True,
                return_tensors="pt",
            ).to(model.device)
            out.append(torch.sigmoid(model(**encoded).logits.float()).cpu().numpy())
    return np.vstack(out)


def f1(truth: Any, predicted: Any) -> float:
    hits = float((truth * predicted).sum())
    if hits == 0:
        return 0.0
    precision = hits / float(predicted.sum())
    recall = hits / float(truth.sum())
    return 2 * precision * recall / (precision + recall)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--model", default="runs/moderation/final")
    args = parser.parse_args()

    here = Path(__file__).resolve().parent
    config = yaml.safe_load((here / args.config).read_text())
    taxonomy = yaml.safe_load((here / config["taxonomy"]).read_text())
    categories = [entry["id"] for entry in taxonomy["categories"]]

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForSequenceClassification.from_pretrained(
        args.model,
        num_labels=len(categories),
        problem_type=config["problem_type"],
        id2label=dict(enumerate(categories)),
        label2id={name: index for index, name in enumerate(categories)},
    )
    # Same round-trip gap as the label count, and it fails later and less obviously:
    # "Cannot handle batch sizes > 1 if no padding token is defined". A classification
    # head reads the last non-padding position, so without this the model cannot batch
    # at all, and the error names padding rather than the checkpoint that lost it.
    model.config.pad_token_id = tokenizer.pad_token_id
    length = config["train"]["max_length"]

    data_dir = here / config["data"]["out_dir"]
    dev = load_jsonl(data_dir / "dev.jsonl")
    test = load_jsonl(data_dir / "test.jsonl")

    dev_scores = score_all(model, tokenizer, dev, length)
    dev_truth = np.array([row["labels"] for row in dev])

    thresholds: dict[str, float] = {}
    for index, category in enumerate(categories):
        best, best_f1 = 0.5, -1.0
        for candidate in config["eval"]["threshold_grid"]:
            value = f1(
                dev_truth[:, index], (dev_scores[:, index] >= candidate).astype(int)
            )
            if value > best_f1:
                best, best_f1 = candidate, value
        thresholds[category] = best

    print("threshold per category, chosen on dev rather than left at 0.5:")
    for category, value in thresholds.items():
        print(f"  {category:<24} {value}")

    test_scores = score_all(model, tokenizer, test, length)
    test_truth = np.array([row["labels"] for row in test])
    grid = np.array([thresholds[c] for c in categories])
    predicted = (test_scores >= grid).astype(int)

    print("\nper category, on the test split:")
    print(f"  {'category':<24} {'support':>8} {'F1':>8}")
    for index, category in enumerate(categories):
        support = int(test_truth[:, index].sum())
        shown = (
            "no data"
            if not support
            else f"{f1(test_truth[:, index], predicted[:, index]):.3f}"
        )
        print(f"  {category:<24} {support:>8} {shown:>8}")

    print("\nper language, the table this project requires:")
    print(f"  {'lang':<6} {'rows':>6} {'macro F1':>10}")
    for language in taxonomy["languages"]:
        mask = np.array([row["language"] == language for row in test])
        if not mask.any():
            print(f"  {language:<6} {0:>6} {'no data':>10}")
            continue
        values = [
            f1(test_truth[mask][:, i], predicted[mask][:, i])
            for i in range(len(categories))
            if test_truth[mask][:, i].sum()
        ]
        macro = sum(values) / len(values) if values else 0.0
        print(f"  {language:<6} {int(mask.sum()):>6} {macro:>10.3f}")

    out = Path(args.model) / "thresholds.json"
    out.write_text(json.dumps(thresholds, indent=2))
    print(f"\nthresholds written to {out}")
    print(
        "\nPublish the rows reading 'no data'. The rule is that a language "
        "which underperforms gets its number published rather than dropped from the "
        "table, and a language with no test data is that claim made earlier."
    )


if __name__ == "__main__":
    main()
