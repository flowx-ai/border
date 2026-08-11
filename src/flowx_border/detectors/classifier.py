# SPDX-License-Identifier: Apache-2.0
"""One detector class for every sequence-classification model in the set.

Seven detectors share this: `injection`, `regulated_advice`, `toxicity`, `nsfw`, `bias`,
`gibberish` and `politeness`. They are all XLM-RoBERTa base with a classification head,
so
seven files would have been seven copies of the same forty lines, and a bug fixed in one
of
them would live on in six. The differences are entirely data: which model id,
which labels, which threshold, and whether the head is read with sigmoid or argmax. All
four come from the model's own config and the policy, so none of them is code here.

Two things this class decides, and both matter
---------------------------------------------

**A long text is the maximum over its windows, not its average.** A document with one
abusive paragraph is abusive. Averaging would let a long benign document bury a short
toxic
passage, which is precisely the evasion a caller is protected against. So each window is
scored and the highest score per label wins. The consequence is worth stating: on a long
document the false-positive rate is the per-window rate compounded over the windows, so
a
detector that fires on 1 in 100 windows fires on roughly 1 in 10 hundred-window
documents.
That is the right trade for a guard, and it is why the threshold is calibrated rather
than
guessed.

**The head is read the way its config says.** `problem_type` decides between sigmoid per
label against a threshold and argmax over exclusive classes. Reading a multi-label head
with argmax reports one label where several apply; reading a single-label head with a
threshold reports several where the model meant one. The export pipeline learned this
the
hard way when a verification step gated on the wrong reading and failed a model that was
answering correctly.

Findings carry the label the model emits, lowercased, and the policy's action. One
whose model is not published raises from `warm`, naming the repo, because CLAUDE.md
requires an unavailable detector to fail loudly rather than return no findings.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Final

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.catalogue import CATALOGUE
from flowx_border.types import Finding

if TYPE_CHECKING:
    import numpy as np

#: How many scored texts to keep per detector. Unlike `pii`, no second detector shares a
#: classifier's result, so this only helps a caller who scans the same text twice.
_CACHE_ENTRIES: Final = 2

#: Overlap between windows, in tokens. Smaller than pii's because a classifier scores a
#: whole window rather than locating a span inside it, so a boundary costs less.
DEFAULT_OVERLAP: Final = 8


class ClassifierDetector:
    """A sequence-classification detector, parameterised by model and catalogue."""

    def __init__(
        self, detector_id: str, model_id: str, *, threads: int | None = None
    ) -> None:
        spec = CATALOGUE[detector_id]
        self.id = detector_id
        self.tier = spec.tier
        self.sides = spec.sides
        self._model_id = model_id
        self._threads = threads
        self._labels: dict[int, str] | None = None
        self._multi_label: bool | None = None
        self._cache: dict[tuple[str, int, int, int], dict[str, float]] = {}
        self._lock = threading.Lock()

        self.model_id: str | None = None
        self.model_revision: str | None = None
        self.weights_sha256: str | None = None

    # ------------------------------------------------------------------ lifecycle

    def warm(self) -> None:
        """Load the weights and read the head shape from the model's own config.

        Raises ModelUnavailableError, naming the repo, when the artifact is not
        published.
        A detector that returned no findings instead would be indistinguishable from a
        clean scan, which is the failure this library refuses everywhere.
        """
        from flowx_border.models.onnx import DEFAULT_THREADS
        from flowx_border.models.onnx import warm as warm_session
        from flowx_border.models.registry import attestation_for

        threads = DEFAULT_THREADS if self._threads is None else self._threads
        warm_session(self._model_id, threads=threads)
        self._read_config()
        self.model_id, self.model_revision, self.weights_sha256 = attestation_for(
            self._model_id
        )

    def forget(self) -> None:
        """Drop the score cache. For measurement; see PiiDetector.forget."""
        with self._lock:
            self._cache.clear()

    def _read_config(self) -> None:
        """Labels and head shape, from the published config rather than a table here.

        Hardcoding either would break silently the day a revision changes: every finding
        would carry a confidently wrong label, or the head would be read the wrong way.
        """
        from huggingface_hub import hf_hub_download

        from flowx_border.models.registry import spec_for

        spec = spec_for(self._model_id)
        path = hf_hub_download(
            repo_id=spec.repo, filename="config.json", revision=spec.revision
        )
        config = json.loads(Path(path).read_text(encoding="utf-8"))
        id2label = config.get("id2label") or {}
        if not id2label:
            raise RuntimeError(
                f"{spec.repo} config.json has no id2label, so findings could not be "
                "labelled. Republish the model with its label map."
            )
        self._labels = {
            int(index): str(label).lower() for index, label in id2label.items()
        }
        self._multi_label = config.get("problem_type") == "multi_label_classification"

    # ------------------------------------------------------------------ inference

    def _tokenizer(self) -> object:
        from huggingface_hub import hf_hub_download
        from tokenizers import Tokenizer

        from flowx_border.models.registry import spec_for

        spec = spec_for(self._model_id)
        path = hf_hub_download(
            repo_id=spec.repo, filename="tokenizer.json", revision=spec.revision
        )
        tokenizer = Tokenizer.from_file(path)
        # Truncation off for the same reason as in pii: these tokenizers ship with
        # truncation at the training length, and leaving it on means a long document is
        # scored on its first paragraph while the rest is reported clean.
        tokenizer.no_truncation()
        tokenizer.no_padding()
        return tokenizer

    def scores(self, text: str, threads: int, overlap: int) -> dict[str, float]:
        """The highest score per label across every window. Memoised.

        Maximum rather than mean: a document with one abusive paragraph is abusive, and
        averaging would let a long benign document bury a short toxic passage.
        """
        import numpy as np

        from flowx_border.models.onnx import session_for

        loaded = session_for(self._model_id, threads=threads)
        size = loaded.spec.trained_max_length - 2
        key = (text, threads, size, overlap)

        with self._lock:
            hit = self._cache.get(key)
        if hit is not None:
            return hit

        if self._labels is None:
            self._read_config()
        labels = self._labels or {}

        tokenizer = self._tokenizer()
        encoded = tokenizer.encode(  # type: ignore[attr-defined]
            text, add_special_tokens=False
        )
        ids = list(encoded.ids)
        if not ids:
            return {}

        bos = int(tokenizer.token_to_id("<s>") or 0)  # type: ignore[attr-defined]
        eos = int(tokenizer.token_to_id("</s>") or 2)  # type: ignore[attr-defined]

        from flowx_border.detectors.pii import _windows

        best: dict[str, float] = {}
        for start, end in _windows(len(ids), max(1, size), overlap):
            window = np.asarray([[bos, *ids[start:end], eos]], dtype=np.int64)
            logits = np.asarray(
                loaded.run(
                    {"input_ids": window, "attention_mask": np.ones_like(window)}
                )[0],
                dtype=np.float64,
            )[0]
            row = self._read_head(logits)
            for index, score in enumerate(row):
                label = labels.get(index)
                if label is None:
                    continue
                best[label] = max(best.get(label, 0.0), float(score))

        with self._lock:
            if len(self._cache) >= _CACHE_ENTRIES:
                self._cache.pop(next(iter(self._cache)))
            self._cache[key] = best
        return best

    def _read_head(self, logits: np.ndarray) -> np.ndarray:
        """Sigmoid per label, or softmax over exclusive classes, as the config says."""
        import numpy as np

        if self._multi_label:
            return 1.0 / (1.0 + np.exp(-logits))  # type: ignore[no-any-return]
        shifted = logits - logits.max()
        exponentiated = np.exp(shifted)
        return exponentiated / exponentiated.sum()  # type: ignore[no-any-return]

    # ------------------------------------------------------------------ the contract

    def run(
        self,
        text: str,
        cfg: DetectorConfig,
        ctx: Context,  # noqa: ARG002 - the Detector protocol fixes this signature
    ) -> list[Finding]:
        from flowx_border.models.onnx import DEFAULT_THREADS

        if not text.strip():
            return []

        threads = int(cfg.options.get("threads", self._threads or DEFAULT_THREADS))
        overlap = int(cfg.options.get("window_overlap", DEFAULT_OVERLAP))
        scored = self.scores(text, threads, overlap)

        if self._multi_label:
            # Every label over the threshold is a finding, because these labels are not
            # exclusive: text can be an insult and a threat at once, and reporting one
            # lose the other.
            firing = [
                (label, score)
                for label, score in scored.items()
                if score >= cfg.threshold
            ]
        else:
            # Argmax, and only when it is not the implicit negative class. A
            # single-label
            # head always names a winner, so reporting it unconditionally would mean a
            # finding on every scan.
            if not scored:
                return []
            label, score = max(scored.items(), key=lambda item: item[1])
            negative = label in ("o", "none", "benign", "neutral", "supported", "ok")
            firing = [] if negative else [(label, score)]

        return [
            Finding(
                detector_id=self.id,
                tier=self.tier,
                label=label,
                score=round(score, 6),
                # No span. A classifier scores a whole text, and inventing a span over
                # all
                # of it would make redaction replace the entire message with a
                # placeholder.
                span=None,
                action=cfg.on_fail,
                model_id=self.model_id,
                model_revision=self.model_revision,
            )
            for label, score in sorted(firing, key=lambda item: (-item[1], item[0]))
        ]
