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
from typing import Final, NamedTuple

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.catalogue import CATALOGUE
from flowx_border.detectors.claim_conflict import conflict
from flowx_border.detectors.multilingual import sentences
from flowx_border.types import Finding

MODEL_ID: Final = "groundedness"

#: What claim_conflict.conflict returns: a label and the tokens that caused it.
_Conflict = tuple[str, tuple[str, ...]] | None

#: The label whose presence means "no finding". Read from the model's own config at warm
#: rather than assumed, and checked against this, so a re-export that renamed the
#: classes fails loudly instead of inverting every verdict.
SUPPORTED: Final = "supported"
REPORTABLE: Final = ("unsupported", "contradicted")


class LabelScheme(NamedTuple):
    """A label set this detector knows how to read, and which member means "no finding".

    Two exist because the objective changed. The three-way scheme separates invention
    from disagreement, which an operator reading a record wants. The binary trains
    the decision a caller acts on: `REPORTABLE` already collapses the other two, so a
    three-way softmax optimises a boundary nobody sees. Measured 2026-08-17, the binary
    objective bought no accuracy on the hand-written probes, 29 of 42 either way, and it
    moved the temporal-contradiction probe from `supported` at 0.9995 to 0.7757, the
    first time in seven candidates that probe came within reach of a threshold.

    Matched against the artifact's own `id2label` rather than assumed, so a re-export
    that renamed a class fails loudly instead of inverting every verdict.
    """

    grounded: str
    reportable: tuple[str, ...]

    @property
    def names(self) -> frozenset[str]:
        return frozenset({self.grounded, *self.reportable})


THREE_WAY: Final = LabelScheme(SUPPORTED, REPORTABLE)
BINARY: Final = LabelScheme("grounded", ("not_grounded",))
SCHEMES: Final = (THREE_WAY, BINARY)

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
        # Which label set the loaded artifact uses. Set at warm by
        # `_read_config`, never guessed.
        self._scheme: LabelScheme = THREE_WAY
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
        named = frozenset(labels.values())
        scheme = next((s for s in SCHEMES if s.names == named), None)
        if scheme is None:
            known = " or ".join(str(sorted(s.names)) for s in SCHEMES)
            raise RuntimeError(
                f"{path} declares labels {sorted(named)}, and this detector reads "
                f"{known}. A mismatch would invert verdicts silently, so it is refused "
                "here rather than discovered from a scan."
            )
        self._labels = labels
        self._scheme = scheme

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

        grounded_label = self._scheme.grounded
        # None keeps the argmax behaviour every three-way artifact shipped with. A
        # binary
        # artifact needs a number: its argmax is 0.5, and the temporal probe
        # sits at 0.7757, so argmax alone puts that case back on the grounded side. See
        # LabelScheme.
        grounded_min_raw = options.get("grounded_min")
        grounded_min = None if grounded_min_raw is None else float(grounded_min_raw)
        use_rules = bool(options.get("rules", True))

        for start, end in spans:
            sentence = text[start:end].strip()
            # A sentence is grounded if any one source grounds it, so the rule has to
            # veto
            # per source rather than over the set: a numeric conflict with source B says
            # nothing when source A states the figure the sentence quotes.
            grounded_somewhere = False
            fallback: tuple[dict[str, float], _Conflict] | None = None
            for source in sources:
                scored = self.judge(source, sentence, threads)
                ruled = conflict(source, sentence) if use_rules else None
                if ruled is None and self._reads_grounded(scored, grounded_min):
                    grounded_somewhere = True
                    break
                # Tracked as the full distribution of the closest source rather than
                # just
                # its grounded score, because the reported label has to say whether the
                # alternative was invention or disagreement.
                if (
                    fallback is None
                    or scored[grounded_label] > fallback[0][grounded_label]
                ):
                    fallback = (scored, ruled)
            if grounded_somewhere or fallback is None:
                continue

            best, ruled = fallback
            if ruled is not None:
                # Deterministic, so it carries score 1.0 and ignores cfg.threshold: a
                # figure that disagrees with its source is not a confidence judgement.
                #
                # The disagreeing token is deliberately not put in the label, and the
                # first version of this did exactly that. Two reasons, the second being
                # the important one. `Finding.label` is a constrained identifier, so
                # pydantic refused `numeric_conflict:3.2` outright. And that token is a
                # fragment of the caller's own text, which an evidence record must never
                # contain: it holds hashes, and a figure quoted into a label would be
                # raw
                # user text inside an artifact designed to carry none. The span already
                # says which sentence, so a caller holding the text can see the number.
                label, _tokens = ruled
                out.append(
                    Finding(
                        detector_id=self.id,
                        tier=self.tier,
                        label=label,
                        score=1.0,
                        span=(start, end),
                        action=cfg.on_fail,
                        model_id=self.model_id,
                        model_revision=self.model_revision,
                    )
                )
                continue

            verdict = self._verdict(best, grounded_min)
            if verdict == grounded_label:
                continue
            score = best[verdict]
            # `grounded_min` supersedes `cfg.threshold` rather than combining with it,
            # and
            # the first version of this applied both. That is incoherent on a two-class
            # head: a sentence just under the grounded bar has a correspondingly small
            # not-grounded score, so the temporal probe failed the bar at 0.7681 and was
            # then discarded for scoring only 0.2319 against a 0.5 threshold. Failing
            # the
            # bar and failing it hard enough are not two questions, and a policy that
            # sets
            # `grounded_min` has already said where its line is.
            if grounded_min is None and score < cfg.threshold:
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

    def _reads_grounded(
        self, scored: dict[str, float], grounded_min: float | None
    ) -> bool:
        grounded_label = self._scheme.grounded
        if grounded_min is None:
            return max(scored, key=lambda label: scored[label]) == grounded_label
        return scored[grounded_label] >= grounded_min

    def _verdict(self, scored: dict[str, float], grounded_min: float | None) -> str:
        """The label to report, which is not always the argmax.

        With `grounded_min` set, a distribution can fail the grounded bar while grounded
        is
        still its highest score. Reporting the argmax then would report `grounded` as a
        finding, so the verdict is the best of the reportable labels instead.
        """
        if self._reads_grounded(scored, grounded_min):
            return self._scheme.grounded
        reportable = [name for name in self._scheme.reportable if name in scored]
        if not reportable:  # pragma: no cover - a scheme always has one
            return max(scored, key=lambda label: scored[label])
        return max(reportable, key=lambda label: scored[label])

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
