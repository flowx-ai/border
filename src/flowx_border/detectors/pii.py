# SPDX-License-Identifier: Apache-2.0
"""T1: personal data, by NER over ONNX.

Backed by `flowxai/piiguard`, an XLM-RoBERTa base tagger over 7 entity types: CARD,
DATE, EMAIL, IBAN, NATIONAL_ID, PERSON, PHONE. BIO tagging, so an entity is a `B-` token
followed by zero or more `I-` tokens of the same type.

What this detector is honest about
----------------------------------

piiguard was trained on 9 of the 26 languages the library supports: en, ro, bg, hu, sl,
hr, de, it, fr. The other 17 are **untested, not covered**. It will return findings for
text in them, because the base model is multilingual, and those findings have no
measured precision or recall behind them. `UNTESTED_LANGUAGES` is exported so a caller
can say so rather than implying 26.

One specific claim not to make: in the training generator, locale `en` is labelled
United Kingdom but uses the German Steuer-IdNr algorithm as a generic numeric
fallback. A real UK NINo carries no checksum so a fallback is defensible, but the
model learned a German-shaped number as a UK identifier. English national IDs are
not checksum validated.

Offsets, which are the hard part
--------------------------------

A finding's span has to index the caller's original string. Three things stand between a
model output and that:

1. The tokenizer is subword, so one entity is several tokens. Offsets come from
   the fast tokenizer, never reconstructed by re-searching the text: searching for the
   decoded token finds the first occurrence, which is the wrong one whenever a name
   appears twice.
2. Long text is windowed, and a window's token indices are local to it. Every offset is
   mapped back through the full-text encoding, so a span found in the fourth window
   still points into the original string.
3. Windows overlap, so a boundary entity is found twice. Duplicates are merged by
   span rather than reported twice.

Cost
----

Measured on an M-series CPU at one thread, INT8: 0.55 ms per token, so 96 tokens
costs about 55 ms and 16 tokens about 9 ms. Latency is linear in tokens, and
windowing makes it linear in text length too. That is the property that matters: a
long document costs proportionally rather than catastrophically. See
tests/test_budgets.py for the stated budget.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import TYPE_CHECKING, Final

from flowx_border.detectors.base import INPUT, OUTPUT, Context, DetectorConfig
from flowx_border.types import Finding

if TYPE_CHECKING:
    import numpy as np
    from tokenizers import Tokenizer

MODEL_ID: Final = "piiguard"

#: Entity types the model tags, lowercased. The engine builds its placeholder by
#: upper-casing the label, so `email` becomes `[EMAIL]`.
ENTITY_TYPES: Final[tuple[str, ...]] = (
    "card",
    "date",
    "email",
    "iban",
    "national_id",
    "person",
    "phone",
)

#: The 9 locales piiguard was trained on, from configs/cross/pii_multi.yaml in the
#: training repo. Not the hub tags, which advertise two.
TRAINED_LANGUAGES: Final[frozenset[str]] = frozenset(
    {"en", "ro", "bg", "hu", "sl", "hr", "de", "it", "fr"}
)

#: The other 17 of the 26. Findings in these are unmeasured, not absent.
UNTESTED_LANGUAGES: Final[tuple[str, ...]] = tuple(
    sorted(
        {
            "cs",
            "da",
            "nl",
            "el",
            "es",
            "et",
            "fi",
            "ga",
            "lv",
            "lt",
            "mt",
            "pl",
            "pt",
            "sk",
            "sv",
            "tr",
            "az",
        }
    )
)

#: How many inference results to keep. Two covers the input and the output side of one
#: exchange, which is the case that matters: `output_leakage` scans the same text `pii`
#: just scanned, and without this it paid for the encoder a second time.
_CACHE_ENTRIES: Final = 2

#: Tokens of overlap between windows. An entity longer than this straddling a boundary
#: can still be cut, and 16 subword tokens is far longer than any of these entity types.
DEFAULT_OVERLAP: Final = 16

_TOKENIZER_LOCK = threading.Lock()
_TOKENIZER: dict[str, Tokenizer] = {}


def _tokenizer(model_id: str = MODEL_ID) -> Tokenizer:
    """The fast tokenizer that ships with the model, loaded once.

    From the model's own repo and revision, never a similarly-named one: character
    offsets are only correct for the tokenizer the model was trained with, and a span
    computed against a different vocabulary is wrong rather than approximate.
    """
    cached = _TOKENIZER.get(model_id)
    if cached is not None:
        return cached
    with _TOKENIZER_LOCK:
        cached = _TOKENIZER.get(model_id)
        if cached is not None:
            return cached

        from huggingface_hub import hf_hub_download
        from tokenizers import Tokenizer

        from flowx_border.models.registry import spec_for

        spec = spec_for(model_id)
        path = hf_hub_download(
            repo_id=spec.repo, filename="tokenizer.json", revision=spec.revision
        )
        tokenizer = Tokenizer.from_file(path)

        # Truncation off, and this is not optional.
        #
        # piiguard's published tokenizer.json carries `truncation: {max_length: 96}`
        # from training. With it left on, `encode` silently returns the first 96 tokens
        # of any text: measured on 2026-08-11, a 1701 character document encoded to 96
        # tokens, so windowing never saw past the first paragraph and the rest of the
        # document was reported clean. That is the worst shape of bug this library can
        # have, a confident all-clear on text nobody looked at.
        #
        # Windowing is this detector's job, done against the full token sequence, so the
        # tokenizer must hand over all of it. Disabled here, at the single point where
        # the tokenizer is constructed, rather than at each call site where one omission
        # would reintroduce it.
        tokenizer.no_truncation()
        tokenizer.no_padding()

        _TOKENIZER[model_id] = tokenizer
        return tokenizer


def _label_map(model_id: str = MODEL_ID) -> dict[int, str]:
    """Index to BIO label, from the model's config rather than hardcoded.

    Hardcoding would be shorter and would break silently the day a revision reorders its
    labels: every finding would carry a confidently wrong entity type.
    """
    import json

    from huggingface_hub import hf_hub_download

    from flowx_border.models.registry import spec_for

    spec = spec_for(model_id)
    path = hf_hub_download(
        repo_id=spec.repo, filename="config.json", revision=spec.revision
    )
    with Path(path).open(encoding="utf-8") as handle:
        config = json.load(handle)
    id2label = config.get("id2label") or {}
    if not id2label:
        raise RuntimeError(
            f"{spec.repo} config.json has no id2label, cannot decode tags"
        )
    return {int(index): str(label) for index, label in id2label.items()}


def _softmax(logits: np.ndarray) -> np.ndarray:
    import numpy as np

    shifted = logits - logits.max(axis=-1, keepdims=True)
    exponentiated = np.exp(shifted)
    normalised: np.ndarray = exponentiated / exponentiated.sum(axis=-1, keepdims=True)
    return normalised


def _windows(count: int, size: int, overlap: int) -> list[tuple[int, int]]:
    """Half-open token ranges covering `count` tokens, overlapping by `overlap`.

    The last window is clamped to the end rather than padded, so a 100 token text is two
    windows and not two windows plus an almost-empty third.
    """
    if count <= size:
        return [(0, count)]
    stride = max(1, size - overlap)
    spans = []
    start = 0
    while start < count:
        end = min(start + size, count)
        spans.append((start, end))
        if end == count:
            break
        start += stride
    return spans


class PiiDetector:
    """NER over ONNX, windowed, with spans that index the caller's string."""

    id = "pii"
    tier = "T1"
    sides = frozenset({INPUT, OUTPUT})

    # Read by evidence.attest, which is why these are attributes rather than locals. A
    # record has to say which weights produced a finding.
    model_id: str | None = None
    model_revision: str | None = None
    weights_sha256: str | None = None

    def __init__(self, *, threads: int | None = None) -> None:
        self._threads = threads
        self._labels: dict[int, str] | None = None
        # Insertion-ordered, so the oldest entry is the one evicted. See `entities`.
        self._cache: dict[
            tuple[str, int, int, int], dict[tuple[int, int], tuple[str, float]]
        ] = {}
        self._cache_lock = threading.Lock()

    def warm(self) -> None:
        """Load weights and tokenizer, run a throwaway pass, and record the attestation.

        Everything that can touch the network happens here, never in `run`. That is what
        makes constraint 1 hold: with a warm detector, a scan needs no network at all.
        """
        from flowx_border.models.onnx import DEFAULT_THREADS
        from flowx_border.models.onnx import warm as warm_session
        from flowx_border.models.registry import attestation_for

        threads = DEFAULT_THREADS if self._threads is None else self._threads
        warm_session(MODEL_ID, threads=threads)
        _tokenizer()
        self._labels = _label_map()
        self.model_id, self.model_revision, self.weights_sha256 = attestation_for(
            MODEL_ID
        )

    def entities(
        self, text: str, threads: int, window_tokens: int | None, overlap: int
    ) -> dict[tuple[int, int], tuple[str, float]]:
        """Every entity the model finds, before any policy filtering. Memoised.

        Split out from `run` so that `output_leakage` can reuse the inference rather than
        repeat it. The two detectors already shared the session, which saved 279 MB of
        weights, but each still ran its own encoder pass over the same text: measured
        2026-08-11, 51 ms each and 116 ms for a full output-side scan, so about half of
        that was duplicated work for an identical answer.

        The cache key is the text and the window geometry, and deliberately not the
        threshold or the entity list, because those filter a result rather than change it.
        Two entries, which covers the input and output side of one exchange; a scan of a
        third text evicts the oldest.

        Correctness rests on constraint 6: the same text through the same weights gives
        the same answer, so a cached result cannot go stale within a process. The cache
        holds spans and scores, never a copy of the caller's text beyond the key itself,
        and it is process-local.
        """
        import numpy as np

        from flowx_border.models.onnx import session_for

        loaded = session_for(MODEL_ID, threads=threads)
        size = (
            loaded.spec.trained_max_length if window_tokens is None else window_tokens
        ) - 2
        key = (text, threads, size, overlap)

        with self._cache_lock:
            hit = self._cache.get(key)
        if hit is not None:
            return hit

        if self._labels is None:
            self._labels = _label_map()
        labels = self._labels
        tokenizer = _tokenizer()

        # Encode once, without special tokens, so that a token index maps directly to a
        # character offset in the caller's string for every window.
        encoded = tokenizer.encode(text, add_special_tokens=False)
        ids: list[int] = list(encoded.ids)
        offsets: list[tuple[int, int]] = list(encoded.offsets)
        if not ids:
            return {}

        bos, eos = self._special_ids(tokenizer)
        found: dict[tuple[int, int], tuple[str, float]] = {}
        for start, end in _windows(len(ids), max(1, size), overlap):
            window_ids = [bos, *ids[start:end], eos]
            array = np.asarray([window_ids], dtype=np.int64)
            logits = loaded.run(
                {"input_ids": array, "attention_mask": np.ones_like(array)}
            )[0]
            probabilities = _softmax(np.asarray(logits, dtype=np.float64))[0]

            # Drop the two special tokens: they carry no character offset, and their
            # predictions are not about any part of the text.
            for span, entity, score in self._decode(
                probabilities[1:-1], offsets[start:end], labels
            ):
                # The same entity found in two overlapping windows keeps the higher
                # score, so a boundary-truncated view does not beat a complete one.
                previous = found.get(span)
                if previous is None or score > previous[1]:
                    found[span] = (entity, score)

        merged = self._merge_runs(text, self._snap_to_words(text, found))
        with self._cache_lock:
            if len(self._cache) >= _CACHE_ENTRIES:
                self._cache.pop(next(iter(self._cache)))
            self._cache[key] = merged
        return merged

    def forget(self) -> None:
        """Drop the inference cache.

        For measurement, and only for measurement. tests/test_budgets.py calls it between
        timed iterations, because repeating one text would otherwise turn every reading
        after the first into a cache hit and a budget suite that measures cache hits
        measures nothing while still passing green.
        """
        with self._cache_lock:
            self._cache.clear()

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
        window_tokens = cfg.options.get("window_tokens")
        overlap = int(cfg.options.get("window_overlap", DEFAULT_OVERLAP))
        wanted = self._wanted_entities(cfg)

        merged = {
            span: value
            for span, value in self.entities(
                text,
                threads,
                None if window_tokens is None else int(window_tokens),
                overlap,
            ).items()
            if value[0] in wanted
        }
        return [
            Finding(
                detector_id=self.id,
                tier=self.tier,
                label=entity,
                score=round(score, 6),
                span=span,
                action=cfg.on_fail,
                model_id=self.model_id,
                model_revision=self.model_revision,
            )
            for span, (entity, score) in sorted(merged.items())
            if score >= cfg.threshold
        ]

    # ------------------------------------------------------------------ internals

    def _wanted_entities(self, cfg: DetectorConfig) -> frozenset[str]:
        """Which entity types this policy asks for.

        An unknown name raises. A policy asking for `creditcard` when the model tags
        `card` would otherwise disable card detection and report success, which is the
        same silent-no-op the policy loader refuses for detector ids.
        """
        requested = cfg.options.get("entities")
        if not requested:
            return frozenset(ENTITY_TYPES)
        names = frozenset(str(name).strip().lower() for name in requested)
        unknown = sorted(names - set(ENTITY_TYPES))
        if unknown:
            raise ValueError(
                f"pii: unknown entity type(s) {', '.join(unknown)}. This model tags "
                f"{', '.join(ENTITY_TYPES)}. A misspelled type would silently disable "
                "that check."
            )
        return names

    @staticmethod
    def _snap_to_words(
        text: str, found: dict[tuple[int, int], tuple[str, float]]
    ) -> dict[tuple[tuple[int, int], str], float]:
        """Widen every span to the whitespace-delimited word it sits inside.

        Necessary because the model's tagging drops out mid-entity. Measured on
        2026-08-11: `bob.smith@example.co.uk` was tagged only as far as
        `bob.smith@example`, and `Ionescu` only as far as `Ion`. Redacting those spans
        produces `[EMAIL].co.uk` and `[PERSON]escu`, which leaks the domain and the rest
        of the surname. A partially redacted word is a leaked word, so a span is snapped
        outward to its word before anything else happens to it.

        Trailing and leading sentence punctuation is then trimmed, because expanding
        `1990.` to the word includes the full stop, and a placeholder that eats the
        sentence's punctuation is a needless change to the caller's text. Punctuation
        inside a word is kept: it is what an email and an IBAN are made of.

        The trade is over-redaction within one word. A span that widens to cover a
        letter it should not have is a cosmetic error; a span that stops short of the
        end of an email address is a disclosure.
        """
        trim = ",.;:!?\"')]}»”’…"
        lead = "\"'([{«“‘"
        out: dict[tuple[tuple[int, int], str], float] = {}
        for (start, end), (entity, score) in found.items():
            while start > 0 and not text[start - 1].isspace():
                start -= 1
            while end < len(text) and not text[end].isspace():
                end += 1
            while end > start and text[end - 1] in trim:
                end -= 1
            while start < end and text[start] in lead:
                start += 1
            if end > start:
                # Keyed by span *and* label, so every label a word attracted keeps its
                # vote. Collapsing to a single winner here is what let one PERSON
                # subword inside bob.smith@example.co.uk outrank four EMAIL fragments
                # and rename the whole address. Within one (span, label), the higher
                # score wins, which is the overlapping-window case.
                key = ((start, end), entity)
                if score > out.get(key, -1.0):
                    out[key] = score
        return out

    @staticmethod
    def _merge_runs(
        text: str, found: dict[tuple[tuple[int, int], str], float]
    ) -> dict[tuple[int, int], tuple[str, float]]:
        """Join spans separated by no whitespace into one span.

        BIO decoding alone is not enough for this model. It tags most subwords of an
        email as `B-EMAIL` rather than a `B-` followed by `I-`, so strict decoding turns
        `bob.smith@example.co.uk` into eight findings: 'bob', '.', 'smith', '@', 'ex',
        and so on. Worse, it sometimes tags a subword in the middle of an email as
        PERSON, which splits the run by label as well.

        So any two findings with no whitespace between them are merged, even across
        differing labels, and the merged span takes the label with the greatest total
        score. This deliberately prefers covering the whole sensitive run over
        preserving each subword's label, for one reason: `[EMAIL]smith@example.co.uk` is
        a leaked email address, while an over-merged span is at worst a placeholder that
        swallows a neighbouring character.

        Whitespace is the boundary because it is the one signal that survives every
        script here. Multi-word entities are already handled correctly by BIO: the model
        does emit `B-PERSON I-PERSON` for `Marie Dubois`, so merging across a space is
        neither needed nor safe, since it would join two adjacent distinct people.
        """
        if not found:
            return {}

        out: dict[tuple[int, int], tuple[str, float]] = {}
        # Scores per label within the current run, kept as a list so the merged score
        # can be the mean of the winning label's fragments rather than a sum that grows
        # with how finely the tokenizer happened to split the text.
        scores: dict[str, list[float]] = {}
        start = end = -1

        def flush() -> None:
            if start < 0:
                return
            best = max(scores, key=lambda name: sum(scores[name]))
            winning = scores[best]
            out[(start, end)] = (best, sum(winning) / len(winning))

        for ((next_start, next_end), entity), score in sorted(found.items()):
            gap = text[end:next_start] if start >= 0 and next_start > end else ""
            contiguous = start >= 0 and (
                next_start <= end or not any(c.isspace() for c in gap)
            )
            if contiguous:
                end = max(end, next_end)
            else:
                flush()
                start, end, scores = next_start, next_end, {}
            scores.setdefault(entity, []).append(score)

        flush()
        return out

    @staticmethod
    def _special_ids(tokenizer: Tokenizer) -> tuple[int, int]:
        """The <s> and </s> ids, asked of the tokenizer rather than assumed.

        XLM-R uses 0 and 2, and hardcoding that works until it does not.
        """
        bos = tokenizer.token_to_id("<s>")
        eos = tokenizer.token_to_id("</s>")
        if (
            bos is None or eos is None
        ):  # pragma: no cover - would mean a different family
            raise RuntimeError(
                "tokenizer has no <s>/</s>; this model is not XLM-R shaped"
            )
        return int(bos), int(eos)

    @staticmethod
    def _decode(
        probabilities: np.ndarray,
        offsets: list[tuple[int, int]],
        labels: dict[int, str],
    ) -> list[tuple[tuple[int, int], str, float]]:
        """BIO decode one window into character spans.

        A span runs from a `B-X` through any immediately following `I-X`. An `I-X` with
        no preceding `B-X` starts a span anyway: the model does emit that, and dropping
        it would silently miss an entity rather than report a slightly ragged one.

        The score is the mean over the span's tokens. Mean rather than the first
        token's, because a span whose opening token is confident and whose remainder is
        not is less certain than its first token suggests.
        """
        out: list[tuple[tuple[int, int], str, float]] = []
        current: str | None = None
        start_char = 0
        end_char = 0
        scores: list[float] = []

        def flush() -> None:
            if current is not None and scores:
                out.append(((start_char, end_char), current, sum(scores) / len(scores)))

        limit = min(len(probabilities), len(offsets))
        for index in range(limit):
            row = probabilities[index]
            best = int(row.argmax())
            tag = labels.get(best, "O")
            token_start, token_end = offsets[index]

            # A token with an empty offset contributes no characters. Continuing through
            # it keeps a multi-token entity together.
            if token_start == token_end:
                continue

            if tag == "O":
                flush()
                current, scores = None, []
                continue

            prefix, _, entity = tag.partition("-")
            entity = entity.lower()
            if prefix == "B" or current != entity:
                flush()
                current = entity
                start_char, end_char = token_start, token_end
                scores = [float(row[best])]
            else:
                end_char = token_end
                scores.append(float(row[best]))

        flush()
        return out
