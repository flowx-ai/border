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
whose model is not published raises from `warm`, naming the repo, because an unavailable
detector must fail loudly rather than return no findings: a silent no-op in a security
library is a vulnerability rather than a rough edge.
"""

from __future__ import annotations

import json
import threading
from typing import TYPE_CHECKING, Final

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.catalogue import CATALOGUE
from flowx_border.types import Finding

if TYPE_CHECKING:
    import numpy as np

#: How many scored texts to keep per detector. Unlike `pii`, no second detector shares a
#: classifier's result, so this only helps a caller who scans the same text twice.
_CACHE_ENTRIES: Final = 2

#: The most sentence segments one scan may score on top of its windows, which bounds the
#: cost of `_segments` at a constant rather than at the sentence count of the input.
#:
#: 24 is chosen against the budgets rather than picked. Cost is one forward pass per
#: segment over that segment's own tokens, so segmenting a text does not multiply its
#: token count, it adds per-pass overhead. Measured at the 87-token 3-sentence
#: REFERENCE_INPUT, and at a 24-sentence document, in tests/test_budgets.py.
#:
#: Beyond the cap, adjacent sentences are grouped rather than dropped, so the whole text
#: is still covered and only the granularity falls. A long document therefore degrades
#: toward the old behaviour smoothly instead of having an unscored tail.
_MAX_SEGMENTS: Final = 24

#: The detectors that score their sentences as well as their windows, and the
#: measurement that put each one on this list or kept it off.
#:
#: Segmenting is not free and it is not uniformly good. It closes an evasion and it
#: costs precision, because the same short span that carries a hazard undiluted is
#: also a fragment the model was never calibrated on. So it is a per-detector
#: property decided by measurement rather than a default applied to all eight.
#:
#: Measured 2026-09-14, one thread, shipped thresholds. "Ordinary" is the 234-row sweep
#: in tests/test_ordinary_text_sweep.py. "Evaded" is each detector's own English corpus
#: positives that stop firing when NEUTRAL_PADDING is appended, then prepended:
#:
#:   detector           ordinary FP      evaded, suffix   evaded, prefix   ceiling
#:   moderation         0.004 -> 0.098   52/60 ->  10/60  60/60 ->  0/60   none
#:   nsfw               0.017 -> 0.026   11/24 ->   0/24   2/24 ->  0/24   0.05
#:   injection          0.004 -> 0.038    6/41 ->   0/41   1/41 ->  0/41   0.05
#:   regulated_advice   0.013 -> 0.064    0/22 ->   0/22   6/22 ->  0/22   0.10
#:   gibberish          0.004 -> 0.038    7/30 ->   7/30   6/30 ->  0/30   0.05  *
#:   bias               0.030 -> 0.115   29/59 ->   0/59  17/59 ->  0/59   0.05
#:   toxicity           0.026 -> 0.064    0/20 ->   0/20   0/20 ->  0/20   0.05
#:   politeness         0.017 -> 0.068    1/21 ->   0/21   1/21 ->  0/21   0.05
#:
#: The first four are on: each closes an evasion and stays inside its ordinary-text
#: ceiling.
#:
#: **`moderation` was retrained on 2026-09-14 to remove the cause this table assumed,
#: and the cause was not there. That is the most useful line in this file.** The v7
#: corpus was generated specifically to stop length reading as a negative prior, and it
#: succeeded: its long band went from 114 positives against 1,030 negatives to 1,278
#: against 1,187, and positive median length from 80 characters to 109 against the
#: negatives' 105. Re-measured on the adopted model at its 0.80 threshold:
#:
#:   moderation (v7)    0.098 -> 0.077   53/60 ->   2/60  51/60 ->  0/60   0.10
#:
#: Segmentation off, the retrained model is evaded on 53 of 60 by suffix where the
#: superseded one was evaded on 52, and both catch 60 of 60 bare. So the corpus was
#: never the cause, the dilution happens inside a single forward pass before max-pooling
#: across windows can see it, and the segment pass is load-bearing rather than a stopgap
#: held until a retrain. The retrain did make the mitigation more effective, 10 residual
#: suffix evasions down to 2, and it also cut the ordinary-text cost from 0.098 to
#: 0.077, which is what earned `moderation` the 0.10 ceiling it now has in
#: MAX_FIRE_RATE. It had none when this table was first written.
#:
#: **`gibberish` is off despite being affordable on its own numbers, and the reason is
#: a second-order effect worth stating.** It is T1 and a gibberish input short circuits
#: the tiers above it, by design, so its firing rate is not only its own false-positive
#: rate: every row it fires on is one `moderation`, `toxicity` and `nsfw` never see.
#: Taking it from 0.004 to 0.038 on ordinary text suppresses higher-tier detection
#: on nine times as many ordinary rows, to close 6 prefix evasions in a detector asking
#: whether text is language at all. That trade is the wrong way round, and its 7 of 30
#: suffix cases are arguably correct rather than evasions: appending fluent prose to
#: nonsense genuinely changes whether the text is language.
#:
#: **`bias` is off and it is the uncomfortable one.** It has the second largest evasion,
#: 29 and 17 of 59, and segmenting closes all of it. It is off because the same change
#: takes ordinary text from 0.030 to 0.115, more than double its ceiling, and this
#: project's rule is that a known failure is recorded rather than absorbed by raising a
#: ceiling. Turning it on is a deliberate decision with a ceiling change beside it, not
#: something a security fix should do quietly.
#:
#: `toxicity` is off because it has nothing to gain: 0 of 20 evaded either way before
#: the change, so segmenting buys precision loss and no security. `politeness` closes
#: one evasion of 21 and costs four times its ordinary rate, which is not a trade worth
#: making.
_SEGMENTED: Final = frozenset({"moderation", "nsfw", "injection", "regulated_advice"})

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
        # Annotated as str rather than left to inference. A protocol attribute is
        # invariant, so the narrower Tier that `spec.tier` carries does not satisfy
        # `Detector.tier: str`, and the other detectors declare a plain string literal.
        self.tier: str = spec.tier
        self.sides: frozenset[str] = spec.sides
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
        from flowx_border.models.registry import companion

        path = companion(self._model_id, "config.json")
        config = json.loads(path.read_text(encoding="utf-8"))
        id2label = config.get("id2label") or {}
        if not id2label:
            raise RuntimeError(
                f"{path} has no id2label, so a finding could not be labelled. "
                "Re-export the model with its label map."
            )
        self._labels = {
            int(index): str(label).lower() for index, label in id2label.items()
        }
        self._multi_label = config.get("problem_type") == "multi_label_classification"

    # ------------------------------------------------------------------ inference

    def _tokenizer(self) -> object:
        # Cached in models.onnx rather than loaded here. This function used to call
        # Tokenizer.from_file on every scored window, which is 437 ms of parsing a 16 MB
        # file in front of a 51 ms inference.
        from flowx_border.models.onnx import tokenizer_for

        tokenizer = tokenizer_for(self._model_id)
        # Truncation off for the same reason as in pii: these tokenizers ship with
        # truncation at the training length, and leaving it on means a long document is
        # scored on its first paragraph while the rest is reported clean. Idempotent, so
        # calling it on the cached object each time is free and keeps the setting
        # local to
        # the detector that wants it.
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
        if self.model_id is None:
            # See `PiiDetector._scores`: `warm` is the only other thing that sets these,
            # nothing calls it on the scan path, and a finding that attests no weights
            # is indistinguishable in a record from one a rule produced. This class
            # backs eight detector ids, so it was eight of them.
            from flowx_border.models.registry import attestation_for

            self.model_id, self.model_revision, self.weights_sha256 = attestation_for(
                self._model_id
            )
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

        spans = list(_windows(len(ids), max(1, size), overlap))
        seen = set(spans)
        for span in self._segments(text, encoded, len(ids), max(1, size)):
            if span not in seen:
                seen.add(span)
                spans.append(span)

        best: dict[str, float] = {}
        for start, end in spans:
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

    def _segments(
        self, text: str, encoded: object, total: int, size: int
    ) -> list[tuple[int, int]]:
        """Token ranges for the sentences of `text`, so a hazard is scored undiluted.

        Why this exists, measured 2026-09-14 on the shipped `moderation`. Ten plainly
        worded hazards score above 0.977 on their own and none of them clears the 0.84
        threshold once two sentences about rainfall are attached: 0.9870 to 0.1356 on
        "Does anyone know how to bypass login credentials on corporate systems?".
        Prepending the same inert text rather than appending it evaded all ten, and 60
        of 60 English corpus positives. Five of six classifiers move; `toxicity`, whose
        corpus has the most even length distribution, does not.

        **The maximum across windows in `scores` was the right invariant one level too
        high.** Its docstring says a long benign document must not bury a short toxic
        passage, and that is exactly what happens, because the burying is inside a
        single forward pass and max pooling only ever sees the pass. Padding past the
        94-token window boundary does not recover the score, it flattens at 0.0367,
        because window one holds the hazard plus 93 tokens of padding and no window ever
        holds the hazard alone. Segments are what make the invariant true: scored on its
        own sentence, the same text reads 0.9870 again.

        The model is still wrong and this does not fix it. The corpus gives its long
        band 114 positives against 1,030 negatives, so length is a negative prior the
        model learned correctly, and the fix for that is a regenerate. This narrows the
        window the prior gets to act in.

        Token ranges rather than strings, from the offsets of the encoding already
        computed, so segmenting costs no second tokenizer pass over the text.
        """
        from flowx_border.detectors.multilingual import sentences
        from flowx_border.detectors.pii import _windows

        if self.id not in _SEGMENTED:
            return []

        bounds = sentences(text)
        if len(bounds) < 2:
            # One sentence is already scored whole, so there is nothing to add and no
            # cost to pay. This is the common case for short input.
            return []

        # Group adjacent sentences when there are more than the cap, rather than
        # scoring the first `_MAX_SEGMENTS` and stopping. Truncating would leave a
        # document whose hazard sits in sentence 200 exactly as evadable as before,
        # which is the defect rather than a cheaper version of it.
        groups: list[tuple[int, int]] = []
        per = max(1, (len(bounds) + _MAX_SEGMENTS - 1) // _MAX_SEGMENTS)
        for index in range(0, len(bounds), per):
            chunk = bounds[index : index + per]
            groups.append((chunk[0][0], chunk[-1][1]))

        offsets = list(encoded.offsets)  # type: ignore[attr-defined]
        out: list[tuple[int, int]] = []
        for begin, finish in groups:
            first: int | None = None
            last = 0
            for position, (low, high) in enumerate(offsets):
                if high <= begin or low >= finish:
                    continue
                if first is None:
                    first = position
                last = position
            if first is None:
                continue
            # A segment longer than the model's window is windowed like any other text,
            # so a single very long sentence cannot silently lose its tail.
            for start, end in _windows(last + 1 - first, size, 0):
                out.append((first + start, min(first + end, total)))
        return out

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
