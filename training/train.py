# SPDX-License-Identifier: Apache-2.0
"""Fine-tune a multi-label hazard head on Qwen3-0.6B.

A classification head rather than a generative model, for the two reasons the README
gives: a generative verdict costs roughly twenty sequential forward passes to answer what
one pass answers, and it is only reproducible with decoding pinned, which an evidence
record depends on.

The base is adapted with LoRA on the attention projections and the head is trained from
scratch. Those need different learning rates and the difference is not cosmetic: a head
initialised randomly and trained at the base's rate barely moves in three epochs, and
the run then looks like a model that cannot learn the task.

Class imbalance
---------------

Thirteen categories, each rare. With plain BCE the loss is dominated by negatives and
the model learns to predict zero everywhere, which scores well on accuracy and has no
recall. `pos_weight` per category corrects for it, computed from the training split
rather than guessed.

This is the same failure this project has already seen from the other direction:
CLAUDE.md records four detectors reporting F1 0.000 because their thresholds sat at 0.5
while their scores separated well below it. Imbalance produces that shape of result, and
it is why both `pos_weight` here and the threshold search in evaluate.py exist.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np
import torch
import yaml
from torch import nn
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    Trainer,
    TrainingArguments,
)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


class Dataset(torch.utils.data.Dataset):
    def __init__(self, rows: list[dict[str, Any]], tokenizer: Any, max_length: int):
        self.rows = rows
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, index: int) -> dict[str, Any]:
        row = self.rows[index]
        encoded = self.tokenizer(
            row["text"],
            truncation=True,
            max_length=self.max_length,
            padding="max_length",
        )
        item = {key: torch.tensor(value) for key, value in encoded.items()}
        item["labels"] = torch.tensor(row["labels"], dtype=torch.float)
        return item


class WeightedTrainer(Trainer):
    """BCE with a per-category positive weight.

    Without it the loss is dominated by negatives and the model predicts zero for every
    category, which looks like high accuracy and has no recall at all.
    """

    def __init__(self, *args: Any, pos_weight: torch.Tensor, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.pos_weight = pos_weight

    def compute_loss(
        self,
        model: Any,
        inputs: dict[str, Any],
        return_outputs: bool = False,
        **kwargs: Any,
    ) -> Any:
        labels = inputs.pop("labels")
        outputs = model(**inputs)
        weight = self.pos_weight.to(outputs.logits.device)
        loss = nn.BCEWithLogitsLoss(pos_weight=weight)(
            outputs.logits.float(), labels.float()
        )
        return (loss, outputs) if return_outputs else loss


def positive_weights(rows: list[dict[str, Any]], categories: int) -> torch.Tensor:
    """negatives over positives per category, computed rather than guessed.

    Clamped at 50: a category with three positives in ten thousand rows would otherwise
    get a weight that makes its gradient dominate every batch it appears in.
    """
    counts = np.zeros(categories)
    for row in rows:
        counts += np.array(row["labels"])
    total = len(rows)
    weights = np.where(counts > 0, (total - counts) / np.maximum(counts, 1), 1.0)
    return torch.tensor(np.clip(weights, 1.0, 50.0), dtype=torch.float)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--out", default="runs/moderation")
    args = parser.parse_args()

    here = Path(__file__).resolve().parent
    config = yaml.safe_load((here / args.config).read_text())
    taxonomy = yaml.safe_load((here / config["taxonomy"]).read_text())
    categories = [entry["id"] for entry in taxonomy["categories"]]

    data_dir = here / config["data"]["out_dir"]
    train_rows = load_jsonl(data_dir / "train.jsonl")
    dev_rows = load_jsonl(data_dir / "dev.jsonl")
    print(f"train {len(train_rows)}  dev {len(dev_rows)}  categories {len(categories)}")

    tokenizer = AutoTokenizer.from_pretrained(config["base_model"])
    if tokenizer.pad_token is None:
        # Qwen ships no pad token. Reusing eos is the documented approach, and it
        # matters here because the classification head reads the last non-pad position.
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForSequenceClassification.from_pretrained(
        config["base_model"],
        num_labels=len(categories),
        problem_type=config["problem_type"],
        id2label=dict(enumerate(categories)),
        label2id={name: index for index, name in enumerate(categories)},
        dtype=torch.bfloat16 if config["train"]["bf16"] else torch.float32,
    )
    model.config.pad_token_id = tokenizer.pad_token_id

    lora = config["train"]["lora"]
    if lora["enabled"]:
        from peft import LoraConfig, TaskType, get_peft_model

        model = get_peft_model(
            model,
            LoraConfig(
                task_type=TaskType.SEQ_CLS,
                r=lora["r"],
                lora_alpha=lora["alpha"],
                lora_dropout=lora["dropout"],
                target_modules=lora["target_modules"],
                # The head is new and is trained in full rather than adapted.
                modules_to_save=["score"],
            ),
        )
        model.print_trainable_parameters()

    settings = config["train"]
    trainer = WeightedTrainer(
        model=model,
        args=TrainingArguments(
            output_dir=args.out,
            num_train_epochs=settings["epochs"],
            per_device_train_batch_size=settings["batch_size"],
            gradient_accumulation_steps=settings["grad_accum"],
            learning_rate=settings["learning_rate"],
            warmup_ratio=settings["warmup_ratio"],
            weight_decay=settings["weight_decay"],
            bf16=settings["bf16"],
            logging_steps=10,
            eval_strategy="epoch",
            save_strategy="epoch",
            save_total_limit=1,
            # False, and not for tidiness. Reloading a checkpoint rebuilds the
            # PEFT-wrapped classifier from the saved config, and the underlying
            # AutoModelForSequenceClassification comes back with its default two
            # labels while the saved head has thirteen:
            #
            #   size mismatch for base_model.model.score.modules_to_save.default.weight
            #   copying a param with shape [13, 1024], current model has [2, 1024]
            #
            # Training completes and then dies on the reload, which is a confusing
            # place to lose a run. The last epoch is kept instead. With eval loss still
            # falling at the final epoch there is nothing better to load anyway, and if
            # that stops being true the answer is fewer epochs rather than this flag.
            load_best_model_at_end=False,
            report_to=[],
            seed=config["data"]["seed"],
        ),
        train_dataset=Dataset(train_rows, tokenizer, settings["max_length"]),
        eval_dataset=Dataset(dev_rows, tokenizer, settings["max_length"]),
        pos_weight=positive_weights(train_rows, len(categories)),
    )
    trainer.train()

    out = Path(args.out) / "final"
    trainer.save_model(out)
    tokenizer.save_pretrained(out)
    (out / "categories.json").write_text(json.dumps(categories, indent=2))
    print(f"\nsaved to {out}")


if __name__ == "__main__":
    main()
