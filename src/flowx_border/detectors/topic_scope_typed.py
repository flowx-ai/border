# SPDX-License-Identifier: Apache-2.0
"""The typed-decision engine behind `topic_scope`, the default since 2026-09-30.

`topic_scope.py` owns the detector: the policy options, the taxonomy validation and the
findings. This module owns the model, `flowxai/topic-scope-v3`, and answers one question
for it: given a message and a taxonomy, which node is the message about, or none of
them, and how sure is the model.

**What changed from the bi-encoder, and why it is worth a second model.** The bi-encoder
embeds the message and each node separately and compares the vectors. It cannot read a
node described by exclusion (see the `topic_scope` docstring for the deployment that
found out), and it has no answer for "about none of these": the nearest node always
wins, however far away it is. This model reads the message, the question and every node
together in a small decision head, is offered "none of these topics" as an option of its
own, and returns a calibrated probability. On taxonomies from deployment types it never
trained on it picks the right node, or none, for 0.804 of messages against the
bi-encoder's 0.479, over 11,497 rows in the 26 languages. The model card on the hub has
the per-language table.

**Two graphs, and why.** The model's encoding is late: the message, the question and
each node are encoded as separate short sequences and meet only in the head. So the
encoder is a plain graph (`onnx/model.int8.onnx`) and the head is a second one
(`onnx/head.onnx`), and the states that do not depend on the message are cached. The
question is encoded once per process and a taxonomy's nodes once per taxonomy content,
exactly as the bi-encoder's node vectors are. A scan then costs one encoder pass over
the message and one head pass.

Both files come from one repo at one revision, and both are hash-checked at load. The
evidence record attests the revision and the encoder's hash; the revision is a commit,
so it pins the head's bytes too.

**Options are packed, not padded.** The head has no position embedding, so each node's
tokens are concatenated with no padding and a marker points at each node's first token.
That is the function the head was trained as, over fewer positions, and it matters
because the head's cost grows with the square of the total node text.

**Large taxonomies are shortlisted first.** The model was trained on taxonomies of 4 to
37 nodes. Above `MAX_OPTIONS` nodes, the ones nearest the message by the model's own
similarity term (cosine between mean-pooled states, which is part of every node's score
anyway) are kept, and the detector records a `topic_scope_shortlisted` finding. Silently
dropping nodes is the bug the bi-encoder path still has with its `max_nodes` cut, and a
second copy of it was not wanted.

Everything here is deterministic: no sampling, fixed temperatures from the artifact.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    import numpy as np
    from numpy.typing import NDArray

ENCODER_ID: Final = "topic_scope_v3"
HEAD_ID: Final = "topic_scope_v3_head"

#: Nodes the head is offered at most, before the none option. Training offered 4 to 37.
#: The head's cost grows with the square of the total node text: at one thread, torch,
#: 36-token nodes, it measured 69 ms for 30 nodes and 231 ms for 64 (2026-09-30). 40
#: keeps the head and the message's encoder pass inside the T3 budget.
MAX_OPTIONS: Final = 40


@dataclass(frozen=True)
class Offered:
    """One option as the head sees it: its states, cached with the taxonomy."""

    key: str
    states: Any  # (tokens, hidden), float32
    pooled: Any  # (hidden,), L2-normalised mean of `states`


@dataclass(frozen=True)
class Decision:
    """The head's answer over the offered options, in offered order.

    `probabilities[i]` belongs to `keys[i]`. The none option is always last.
    `shortlisted` is how many nodes the taxonomy had when it was more than
    `MAX_OPTIONS`, and 0 otherwise.
    """

    keys: tuple[str, ...]
    probabilities: tuple[float, ...]
    shortlisted: int


def temperature_bucket(options: int) -> str:
    """The calibration bucket for a choice over `options` options, as in training."""
    size = (
        "2"
        if options == 2
        else "3-5"
        if options <= 5
        else "6-10"
        if options <= 10
        else "11+"
    )
    return f"choice:{size}"


class TypedEngine:
    """Loads the two graphs, caches the question and each taxonomy's node states."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._config: dict[str, Any] | None = None
        self._question: Any = None
        self._none: Offered | None = None
        self._taxonomies: dict[str, list[Offered]] = {}

    # ------------------------------------------------------------------ lifecycle

    def warm(self, threads: int) -> None:
        import numpy as np

        from flowx_border.models.onnx import session_for
        from flowx_border.models.onnx import warm as warm_session

        warm_session(ENCODER_ID, threads=threads)
        head = session_for(HEAD_ID, threads=threads)
        d = self._hidden_size()
        ones = np.ones((1, 4), dtype=np.int64)
        head.run(
            {
                "state": np.zeros((1, 4, d), dtype=np.float32),
                "state_mask": ones,
                "question": np.zeros((1, 4, d), dtype=np.float32),
                "question_mask": ones,
                "options": np.zeros((1, 4, d), dtype=np.float32),
                "options_mask": ones,
                "markers": np.array([[0, 2]], dtype=np.int64),
                "option_pooled": np.zeros((1, 2, d), dtype=np.float32),
                "qtype": np.zeros((1,), dtype=np.int64),
            }
        )
        # The question and the none option do not depend on the policy, so they are
        # encoded here, and the tokenizer (437 ms to parse on the reference machine) is
        # loaded with them, rather than inside the first scan.
        self._question_states(threads)
        self._none_option(threads)

    def forget(self) -> None:
        with self._lock:
            self._taxonomies.clear()
            self._question = None
            self._none = None

    def config(self) -> dict[str, Any]:
        """`decision_config.json`: question, none option, token budgets, calibration."""
        if self._config is None:
            from flowx_border.models.registry import companion

            path = companion(ENCODER_ID, "decision_config.json")
            self._config = json.loads(path.read_text(encoding="utf-8"))
        return self._config

    def _hidden_size(self) -> int:
        from flowx_border.models.registry import companion

        config = json.loads(
            companion(ENCODER_ID, "config.json").read_text(encoding="utf-8")
        )
        return int(config["hidden_size"])

    # ------------------------------------------------------------------ encoding

    def _ids(self, text: str, limit: int) -> list[int]:
        from flowx_border.models.onnx import tokenizer_for

        tokenizer = tokenizer_for(ENCODER_ID)
        # Truncated here, per piece, to the budget the model was trained with. The
        # shared tokenizer object is this model's alone, so clearing its own settings is
        # safe.
        tokenizer.no_truncation()
        tokenizer.no_padding()
        ids: list[int] = tokenizer.encode(text, add_special_tokens=False).ids
        return ids[:limit]

    def _encode(self, ids: list[int], threads: int) -> NDArray[np.float32]:
        import numpy as np

        from flowx_border.models.onnx import session_for

        loaded = session_for(ENCODER_ID, threads=threads)
        batch = np.array([ids], dtype=np.int64)
        hidden = loaded.run(
            {"input_ids": batch, "attention_mask": np.ones_like(batch)}
        )[0]
        out: NDArray[np.float32] = np.asarray(hidden[0], dtype=np.float32)
        return out

    def _offered(self, key: str, text: str, threads: int) -> Offered:
        import numpy as np

        cfg = self.config()
        special = cfg["special_tokens"]
        rendered = key if not text else cfg["option_text"].format(key=key, text=text)
        ids = [
            special["mask"],
            *self._ids(rendered, cfg["budget"]["option"]),
            special["sep"],
        ]
        states = self._encode(ids, threads)
        pooled = states.mean(axis=0)
        norm = float(np.linalg.norm(pooled))
        return Offered(key=key, states=states, pooled=pooled / max(norm, 1e-12))

    def _question_states(self, threads: int) -> NDArray[np.float32]:
        if self._question is None:
            cfg = self.config()
            special = cfg["special_tokens"]
            question = cfg["question"]
            text = f"{question['type']} question: {question['text']}"
            ids = [
                special["cls"],
                *self._ids(text, cfg["budget"]["question"]),
                special["sep"],
            ]
            self._question = self._encode(ids, threads)
        states: NDArray[np.float32] = self._question
        return states

    def _none_option(self, threads: int) -> Offered:
        if self._none is None:
            none = self.config()["none_option"]
            self._none = self._offered(none["key"], none["text"], threads)
        return self._none

    def nodes(
        self, digest: str, nodes: list[tuple[str, str]], threads: int
    ) -> list[Offered]:
        """Each (key, description) encoded once per taxonomy content, by `digest`."""
        with self._lock:
            hit = self._taxonomies.get(digest)
        if hit is not None:
            return hit
        encoded = [self._offered(key, text, threads) for key, text in nodes]
        with self._lock:
            self._taxonomies[digest] = encoded
        return encoded

    # ------------------------------------------------------------------ deciding

    def decide(self, text: str, nodes: list[Offered], threads: int) -> Decision:
        import numpy as np

        from flowx_border.models.onnx import session_for

        cfg = self.config()
        special = cfg["special_tokens"]
        state_ids = [
            special["cls"],
            *self._ids(text, cfg["budget"]["state"] - 2),
            special["sep"],
        ]
        state = self._encode(state_ids, threads)

        shortlisted = 0
        if len(nodes) > MAX_OPTIONS:
            # The model's own similarity term, the same cosine the head adds to each
            # score.
            pooled = state.mean(axis=0)
            pooled = pooled / max(float(np.linalg.norm(pooled)), 1e-12)
            nearness = np.array([float(node.pooled @ pooled) for node in nodes])
            keep = sorted(np.argsort(-nearness, kind="stable")[:MAX_OPTIONS].tolist())
            shortlisted = len(nodes)
            nodes = [nodes[i] for i in keep]

        offered = [*nodes, self._none_option(threads)]
        question = self._question_states(threads)
        markers, offset = [], 0
        for option in offered:
            markers.append(offset)
            offset += option.states.shape[0]
        packed = np.concatenate([option.states for option in offered], 0)[None]
        feed: dict[str, NDArray[Any]] = {
            "state": state[None],
            "state_mask": np.ones((1, state.shape[0]), dtype=np.int64),
            "question": question[None],
            "question_mask": np.ones((1, question.shape[0]), dtype=np.int64),
            "options": packed.astype(np.float32),
            "options_mask": np.ones((1, packed.shape[1]), dtype=np.int64),
            "markers": np.array([markers], dtype=np.int64),
            "option_pooled": np.stack([o.pooled for o in offered])[None].astype(
                np.float32
            ),
            "qtype": np.array([cfg["qtypes"][cfg["question"]["type"]]], dtype=np.int64),
        }
        logits = np.asarray(
            session_for(HEAD_ID, threads=threads).run(feed)[0][0], dtype=np.float64
        )
        logits[-1] += float(cfg["none_offset"])
        bucket = cfg["temperatures"].get(temperature_bucket(len(offered)), {})
        temperature = float(bucket.get("temperature", 1.0))
        scaled = (logits - logits.max()) / temperature
        probabilities = np.exp(scaled) / np.exp(scaled).sum()
        return Decision(
            keys=tuple(option.key for option in offered),
            probabilities=tuple(float(p) for p in probabilities),
            shortlisted=shortlisted,
        )
