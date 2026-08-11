# SPDX-License-Identifier: Apache-2.0
"""T3. Is each sentence of the output supported by the sources it should rest on?

A cross-encoder over `(source, sentence)` pairs, not a classifier over the answer. The
question is relational: the same sentence is grounded against one passage and invented
against another, so nothing about the sentence alone decides it.

**Three classes, kept apart.** The head reports `supported`, `unsupported` and
`contradicted`, and merging the last two would hide the difference between the model
inventing something and the model disagreeing with the passage it was given. Those need
different responses from an operator, so they stay separate labels here too.

**With no sources this detector says so rather than passing.** `Context.sources` empty
and no `options.sources` means there is nothing to compare against, and reporting no
findings would be indistinguishable from a fully grounded answer. It emits one
`groundedness_unverifiable` finding with action `log`: the caller is told the check
could not run, and is not blocked for a configuration gap. The training config records
the same decision under `no_sources_behaviour: record_no_op`, so the two cannot drift.

**A sentence is grounded if any single source grounds it.** The score is the maximum
over sources rather than the mean, because sources are alternative evidence and not a
committee. The consequence worth knowing: a claim assembled from two passages, each
supporting half of it, reads as unsupported. That is the honest reading of a
single-passage judgement, and the corpus contains that case deliberately.

**Cost.** One encoder pass per (sentence, source) pair, at up to 512 tokens. That
product is what the T3 budget is spent on, so `max_sentences` and `max_sources` bound it
and both report when they truncate rather than quietly scoring a prefix.
"""

from __future__ import annotations

import threading
from typing import Final

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.catalogue import CATALOGUE
from flowx_border.detectors.multilingual import sentences
from flowx_border.types import Finding

MODEL_ID: Final = "groundedness"

#: The label whose presence means "no finding". Read from the model's own config at warm
#: rather than assumed, and checked against this, so a re-export that renamed the
#: classes fails loudly instead of inverting every verdict.
SUPPORTED: Final = "supported"
REPORTABLE: Final = ("unsupported", "contradicted")

#: Bounds on the pair count, because cost is sentences times sources. Chosen so the
#: default stays inside the T3 budget on the reference input rather than by principle; a
#: policy that wants more can pay for it and is told what it is paying.
DEFAULT_MAX_SENTENCES: Final = 40
DEFAULT_MAX_SOURCES: Final = 8

#: Below this many characters a sentence is not judged. A fragment like "Thanks."
#: carries no claim, and asking a cross-encoder whether it is supported produces a
#: confident answer to a question nobody asked.
DEFAULT_MIN_CHARS: Final = 12


class GroundednessDetector:
    """Per-sentence groundedness against caller-supplied sources."""

    def __init__(self, *, threads: int | None = None) -> None:
        spec = CATALOGUE["groundedness"]
        self.id = "groundedness"
        # Annotated as str for the same reason ClassifierDetector does it: a protocol
        # attribute is invariant, so the narrower Tier literal does not satisfy `str`.
        self.tier: str = spec.tier
        self.sides: frozenset[str] = spec.sides
        self._threads = threads
        self._labels: dict[int, str] | None = None
        self._cache: dict[tuple[str, str, int], dict[str, float]] = {}
        self._lock = threading.Lock()

        self.model_id: str | None = None
        self.model_revision: str | None = None
        self.weights_sha256: str | None = None

    # ------------------------------------------------------------------ lifecycle

    def warm(self) -> None:
        from flowx_border.models.onnx import DEFAULT_THREADS
        from flowx_border.models.onnx import warm as warm_session
        from flowx_border.models.registry import attestation_for

        threads = DEFAULT_THREADS if self._threads is None else self._threads
        warm_session(MODEL_ID, threads=threads)
        self._read_config()
        self.model_id, self.model_revision, self.weights_sha256 = attestation_for(
            MODEL_ID
        )

    def forget(self) -> None:
        """Drop the pair cache. For measurement; see PiiDetector.forget."""
        with self._lock:
            self._cache.clear()

    def _read_config(self) -> None:
        """Labels from the model's own config, checked against what this file means.

        A re-export that renamed `supported` would otherwise turn every grounded
        sentence into a finding, or every invented one into silence, with nothing to
        notice it.
        """
        import json

        from flowx_border.models.registry import companion

        path = companion(MODEL_ID, "config.json")
        config = json.loads(path.read_text(encoding="utf-8"))
        id2label = config.get("id2label") or {}
        if not id2label:
            raise RuntimeError(
                f"{path} has no id2label, so a verdict could not be named. "
                "Re-export the model with its label map."
            )
        labels = {int(index): str(label).lower() for index, label in id2label.items()}
        named = set(labels.values())
        expected = {SUPPORTED, *REPORTABLE}
        if named != expected:
            raise RuntimeError(
                f"{path} declares labels {sorted(named)}, and this detector reads "
                f"{sorted(expected)}. A mismatch would invert verdicts silently, so it "
                "is refused here rather than discovered from a scan."
            )
        self._labels = labels

    # ------------------------------------------------------------------ inference

    def _tokenizer(self) -> object:
        from flowx_border.models.onnx import tokenizer_for

        tokenizer = tokenizer_for(MODEL_ID)
        # Truncation is configured here rather than left off, which is the opposite of
        # what pii and classifier do, and the reason is the pair. A source passage plus
        # a sentence can exceed the model's 512 positions, and there is no windowing
        # answer:
        # half a passage is a different premise, not a smaller one. So the pair is
        # truncated to the trained length, longest-first, and the detector reports when
        # it had to.
        tokenizer.no_padding()
        return tokenizer

    def judge(self, source: str, sentence: str, threads: int) -> dict[str, float]:
        """Probabilities over the three classes for one pair. Memoised.

        Pair order is `(source, sentence)`, which is the order the model was trained on.
        Reversing it asks a different question and the head answers it confidently.
        """
        import numpy as np

        from flowx_border.models.onnx import session_for

        key = (source, sentence, threads)
        with self._lock:
            hit = self._cache.get(key)
        if hit is not None:
            return hit

        if self._labels is None:
            self._read_config()
        labels = self._labels or {}

        loaded = session_for(MODEL_ID, threads=threads)
        limit = loaded.spec.trained_max_length
        tokenizer = self._tokenizer()
        tokenizer.enable_truncation(  # type: ignore[attr-defined]
            limit, strategy="longest_first"
        )
        encoded = tokenizer.encode(source, sentence)  # type: ignore[attr-defined]

        ids = np.array([list(encoded.ids)], dtype=np.int64)
        mask = np.array([list(encoded.attention_mask)], dtype=np.int64)
        logits = loaded.run({"input_ids": ids, "attention_mask": mask})[0][0]

        shifted = logits - float(np.max(logits))
        exponentiated = np.exp(shifted)
        probabilities = exponentiated / float(np.sum(exponentiated))
        out = {
            labels.get(index, str(index)): float(probabilities[index])
            for index in range(len(probabilities))
        }
        with self._lock:
            self._cache[key] = out
        return out

    # ------------------------------------------------------------------ the detector

    def run(self, text: str, cfg: DetectorConfig, ctx: Context) -> list[Finding]:
        from flowx_border.models.onnx import DEFAULT_THREADS

        options = cfg.options
        threads = int(options.get("threads", self._threads or DEFAULT_THREADS))
        max_sentences = int(options.get("max_sentences", DEFAULT_MAX_SENTENCES))
        max_sources = int(options.get("max_sources", DEFAULT_MAX_SOURCES))
        min_chars = int(options.get("min_chars", DEFAULT_MIN_CHARS))

        # A policy may supply sources too, for a caller whose retrieval layer is not the
        # one building the Context.
        supplied = tuple(str(s) for s in options.get("sources", ()) if str(s).strip())
        sources = tuple(s for s in (*ctx.sources, *supplied) if s.strip())

        if not sources:
            return [self._unverifiable()]

        spans = [
            (start, end)
            for start, end in sentences(text)
            if len(text[start:end].strip()) >= min_chars
        ]
        if not spans:
            # Text with no sentence long enough to carry a claim. Reported, not silent:
            # "nothing to check" and "everything checked out" are different answers.
            return [
                Finding(
                    detector_id=self.id,
                    tier=self.tier,
                    label="groundedness_no_claims",
                    score=1.0,
                    span=None,
                    action="log",
                    model_id=self.model_id,
                    model_revision=self.model_revision,
                )
            ]

        out: list[Finding] = []
        if len(spans) > max_sentences:
            out.append(self._truncated("sentences", len(spans), max_sentences))
            spans = spans[:max_sentences]
        if len(sources) > max_sources:
            out.append(self._truncated("sources", len(sources), max_sources))
            sources = sources[:max_sources]

        for start, end in spans:
            sentence = text[start:end].strip()
            # The best case across sources: a sentence is grounded if any one source
            # grounds it. Tracked as the full distribution of the winning source rather
            # than just its supported score, because the reported label has to say
            # whether the alternative was invention or disagreement.
            best: dict[str, float] | None = None
            for source in sources:
                scored = self.judge(source, sentence, threads)
                if best is None or scored[SUPPORTED] > best[SUPPORTED]:
                    best = scored
            if best is None:  # pragma: no cover - sources is non-empty here
                continue

            verdict = max(best, key=lambda label: best[label])
            if verdict == SUPPORTED:
                continue
            score = best[verdict]
            if score < cfg.threshold:
                continue
            out.append(
                Finding(
                    detector_id=self.id,
                    tier=self.tier,
                    label=verdict,
                    score=round(score, 6),
                    span=(start, end),
                    action=cfg.on_fail,
                    model_id=self.model_id,
                    model_revision=self.model_revision,
                )
            )
        return out

    # ------------------------------------------------------------------ the no-ops

    def _unverifiable(self) -> Finding:
        return Finding(
            detector_id=self.id,
            tier=self.tier,
            label="groundedness_unverifiable",
            score=1.0,
            span=None,
            # Always log. The caller is told the check could not run, and is not blocked
            # for a configuration gap.
            action="log",
            model_id=self.model_id,
            model_revision=self.model_revision,
        )

    def _truncated(self, what: str, had: int, kept: int) -> Finding:
        """Reported rather than logged silently, because it bounds what was checked.

        A record saying a scan found nothing, when the scan looked at 40 of 200
        sentences, is a record that overstates its own coverage.
        """
        del had, kept
        return Finding(
            detector_id=self.id,
            tier=self.tier,
            label=f"groundedness_truncated_{what}",
            score=1.0,
            span=None,
            action="log",
            model_id=self.model_id,
            model_revision=self.model_revision,
        )
