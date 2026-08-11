# SPDX-License-Identifier: Apache-2.0
"""T3. Is the input inside the subject matter this deployment is for?

**A bi-encoder, and that is a deliberate substitution.** The published `semantic-mapper`
is a 4B Qwen3 LoRA that generates JSON against a frozen prompt, distributed as GGUF.
Wiring it here would put a generative model inside a detector, which default 4 rules out
at any size, and 4B cannot meet a 300 ms CPU budget when the 278M encoders cost 51 ms.
So this scores cosine similarity between the input and each taxonomy node instead.
Approved by the owner on 2026-08-11, recorded here because it changes what the detector
can answer: a bi-encoder compares meanings, it does not reason about them.
`semantic-mapper` could say why a text belongs to a node; this says how near it is.

**The taxonomy is policy, not weights.** Nodes come from the policy document, so the
same model serves a bank and a health service, and a compliance officer who does not
write Python can change what is in scope. Node text is embedded at first use and cached
against the taxonomy's own content, so editing a description invalidates it.

**Unconfigured is a finding, not a pass.** A policy that enables this detector without a
taxonomy gets `topic_scope_unconfigured` with action `log`. Returning nothing would be
indistinguishable from an on-topic input, which is the failure this library refuses.

**What the score means.** Cosine similarity between L2-normalised mean-pooled
embeddings, rescaled from its own range into 0..1 because `Score` is a
probability-shaped field and a raw cosine can be negative. The rescale is monotonic, so
a threshold in the policy still orders inputs the same way, but it is not a probability
and the docstring says so rather than letting a reader assume calibration nobody
performed.
"""

from __future__ import annotations

import hashlib
import json
import threading
from typing import TYPE_CHECKING, Any, Final

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.catalogue import CATALOGUE
from flowx_border.types import Finding

if TYPE_CHECKING:
    import numpy as np
    from numpy.typing import NDArray

MODEL_ID: Final = "topic_scope"

#: Path separator inside a label. `Label` is `^[a-z][a-z0-9_]{0,63}$`, so a node path
#: cannot travel as `banking/loans`. Two underscores separate the segments and a single
#: one separates words inside a segment, which makes the path recoverable by splitting
#: on `__`. A node whose folded path would exceed the label length is refused at
#: configuration time rather than truncated, because a truncated path is a wrong path.
PATH_SEPARATOR: Final = "__"
LABEL_LIMIT: Final = 64

#: What a matched node's label is prefixed with. Counted against the limit below,
#: because validating the path alone and then prefixing it is how a "cannot truncate"
#: rule turns into a truncation eleven characters later.
LABEL_PREFIX: Final = f"off_topic{PATH_SEPARATOR}"
PATH_LIMIT: Final = LABEL_LIMIT - len(LABEL_PREFIX)

DEFAULT_MAX_NODES: Final = 64


def fold_path(path: str) -> str:
    """A taxonomy path as a label-safe identifier.

    `banking/loans and mortgages` becomes `banking__loans_and_mortgages`.
    """
    segments = [segment.strip() for segment in path.split("/") if segment.strip()]
    folded = []
    for segment in segments:
        kept = [
            character if character.isalnum() else "_" for character in segment.lower()
        ]
        collapsed = "_".join(part for part in "".join(kept).split("_") if part)
        if collapsed:
            folded.append(collapsed)
    return PATH_SEPARATOR.join(folded)


class TopicScopeError(ValueError):
    """A taxonomy this detector cannot express as findings.

    Raised at configuration time rather than at scan time, so a policy author learns
    about it when they write the policy and not from a truncated label in an audit
    record.
    """


class TopicScopeDetector:
    """Nearest-taxonomy-node scoring against a policy-supplied taxonomy."""

    def __init__(self, *, threads: int | None = None) -> None:
        spec = CATALOGUE["topic_scope"]
        self.id = "topic_scope"
        self.tier: str = spec.tier
        self.sides: frozenset[str] = spec.sides
        self._threads = threads
        self._lock = threading.Lock()
        # Keyed by the taxonomy's content hash, so an edited description is a cache
        # miss.
        self._nodes: dict[str, list[tuple[str, str, Any]]] = {}

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
        self.model_id, self.model_revision, self.weights_sha256 = attestation_for(
            MODEL_ID
        )

    def forget(self) -> None:
        with self._lock:
            self._nodes.clear()

    # ------------------------------------------------------------------ embedding

    def _tokenizer(self) -> object:
        from flowx_border.models.onnx import tokenizer_for

        tokenizer = tokenizer_for(MODEL_ID)
        tokenizer.no_padding()
        return tokenizer

    def embed(self, text: str, threads: int) -> NDArray[np.float32]:
        """One L2-normalised mean-pooled embedding.

        Mean-pooled over unmasked positions only. Including the padding would make the
        vector a function of the batch shape, which is the classic bi-encoder bug: the
        same sentence would embed differently depending on what it was measured
        alongside.
        """
        import numpy as np

        from flowx_border.models.onnx import session_for

        loaded = session_for(MODEL_ID, threads=threads)
        tokenizer = self._tokenizer()
        tokenizer.enable_truncation(  # type: ignore[attr-defined]
            loaded.spec.trained_max_length
        )
        encoded = tokenizer.encode(text)  # type: ignore[attr-defined]

        ids = np.array([list(encoded.ids)], dtype=np.int64)
        mask = np.array([list(encoded.attention_mask)], dtype=np.int64)
        hidden = loaded.run({"input_ids": ids, "attention_mask": mask})[0]

        weights = mask[0].astype(np.float32)[:, None]
        summed = (hidden[0] * weights).sum(axis=0)
        count = max(float(weights.sum()), 1.0)
        pooled: NDArray[np.float32] = (summed / count).astype(np.float32)
        norm = float(np.linalg.norm(pooled))
        if norm <= 0.0:
            # An all-padding input, which the caller already filters, but a zero vector
            # would make every cosine 0.0 and read as "equally near every node".
            return pooled
        normalised: NDArray[np.float32] = pooled / norm
        return normalised

    # ------------------------------------------------------------------ the taxonomy

    def _taxonomy(
        self, options: dict[str, Any], threads: int
    ) -> list[tuple[str, str, Any]]:
        """(path, disposition, vector) per node, embedded once per taxonomy content.

        Disposition is `allowed` or `disallowed`. Both are embedded, and the nearest
        node decides, because a taxonomy of only forbidden topics cannot distinguish
        "about something else entirely" from "about the forbidden thing".
        """
        taxonomy = options.get("taxonomy") or {}
        digest = hashlib.sha256(
            json.dumps(taxonomy, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()

        with self._lock:
            hit = self._nodes.get(digest)
        if hit is not None:
            return hit

        nodes: list[tuple[str, str, Any]] = []
        for disposition in ("allowed", "disallowed"):
            for entry in taxonomy.get(disposition, ()):
                path = str(entry.get("path", "")).strip()
                if not path:
                    raise TopicScopeError(
                        f"a {disposition} taxonomy node has no path, so a finding "
                        "could "
                        "not name what it matched"
                    )
                folded = fold_path(path)
                if not folded:
                    raise TopicScopeError(
                        f"taxonomy path {path!r} folds to nothing usable as a label"
                    )
                if len(folded) > PATH_LIMIT:
                    raise TopicScopeError(
                        f"taxonomy path {path!r} folds to {len(folded)} characters, "
                        "and "
                        f"with the {LABEL_PREFIX!r} prefix a finding label allows "
                        f"{PATH_LIMIT}. Shorten the path: a truncated path in an audit "
                        "record is a wrong path, not a shorter one."
                    )
                # The description carries the meaning. Falling back to the path is worse
                # than nothing would be loud, so it is allowed but the path is
                # prose-like by convention.
                text = str(entry.get("description") or path.replace("/", " "))
                nodes.append((folded, disposition, self.embed(text, threads)))

        with self._lock:
            self._nodes[digest] = nodes
        return nodes

    # ------------------------------------------------------------------ the detector

    def run(self, text: str, cfg: DetectorConfig, ctx: Context) -> list[Finding]:
        del ctx
        from flowx_border.models.onnx import DEFAULT_THREADS

        options = cfg.options
        threads = int(options.get("threads", self._threads or DEFAULT_THREADS))
        max_nodes = int(options.get("max_nodes", DEFAULT_MAX_NODES))

        nodes = self._taxonomy(options, threads)
        if not nodes:
            return [
                Finding(
                    detector_id=self.id,
                    tier=self.tier,
                    label="topic_scope_unconfigured",
                    score=1.0,
                    span=None,
                    action="log",
                    model_id=self.model_id,
                    model_revision=self.model_revision,
                )
            ]
        if len(nodes) > max_nodes:
            nodes = nodes[:max_nodes]
        if not text.strip():
            return []

        vector = self.embed(text, threads)
        best_path, best_disposition, best_similarity = "", "", -1.0
        for path, disposition, node in nodes:
            similarity = float((vector * node).sum())
            if similarity > best_similarity:
                best_path, best_disposition, best_similarity = (
                    path,
                    disposition,
                    similarity,
                )

        # Cosine lives in -1..1 and Score is 0..1, so this maps one onto the other. It
        # is monotonic, which is what a policy threshold needs, and it is not a
        # probability.
        score = max(0.0, min(1.0, (best_similarity + 1.0) / 2.0))
        if best_disposition != "disallowed" or score < cfg.threshold:
            return []
        return [
            Finding(
                detector_id=self.id,
                tier=self.tier,
                # Not truncated: `_taxonomy` refused any path that would not fit, so
                # this is inside the limit by construction rather than by clipping.
                label=f"{LABEL_PREFIX}{best_path}",
                score=round(score, 6),
                # The whole input matched, not a span of it. A bi-encoder scores one
                # meaning for the text as a whole, so pointing at a range would claim a
                # precision the method does not have.
                span=None,
                action=cfg.on_fail,
                model_id=self.model_id,
                model_revision=self.model_revision,
            )
        ]
