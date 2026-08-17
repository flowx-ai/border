# SPDX-License-Identifier: Apache-2.0
"""ONNX Runtime sessions: created once, shared, warmed before use.

Three decisions here, each with a cost attached to getting it wrong.

**One session per model id, process wide.** A session holds the weights, so a second
session for the same model is another 279 MB of resident memory. `pii` and
`output_leakage` both use piiguard, and the second must reuse
the session the first loaded. That sharing is what this cache is for, and it is why the
key is the model id rather than the detector id.

**One thread by default.** The library runs inside someone else's application. ONNX
Runtime defaults to using every core, which means a scan on a 16 core host takes 16 away
from the request handler that called it, and under concurrency the threads fight each
other for worse total throughput than one thread each. So the default is 1, and raising
it is a deliberate choice a policy makes. All latency figures quoted anywhere describe
one thread, because that is the configuration that ships.

**Warm before the first real scan.** The first inference on a fresh session pays for
memory arena allocation and kernel selection, and it can be an order of magnitude slower
than the second. A detector's `warm()` runs a throwaway pass here so that cost lands
during startup rather than inside a caller's request, which is the whole reason `warm`
is separate from `run` in the Detector protocol.

Thread safety: the cache is guarded by a lock, and the lock is held across the load. Two
threads calling `session_for` at once must not both build a session and have one discard
279 MB of work. `InferenceSession.run` itself is thread safe, so the lock is not held
during inference.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from pathlib import Path

    import numpy as np
    from tokenizers import Tokenizer

    from flowx_border.models.registry import ModelSpec

# Default intra-op threads. See the module docstring: this is a politeness decision
# about the host application, not a performance one.
DEFAULT_THREADS: Final = 1


@dataclass
class LoadedModel:
    """A warmed session plus what the evidence record needs to say about it."""

    session: Any
    spec: ModelSpec
    path: Path
    threads: int
    # Names the graph actually declares. A model exported without token_type_ids must
    # not be fed one, and feeding a missing input is an error rather than a warning, so
    # the feed is filtered against this.
    input_names: frozenset[str]

    def run(self, feed: dict[str, np.ndarray]) -> list[np.ndarray]:
        """Inference, with the feed filtered to the inputs this graph declares."""
        wanted = {
            name: value for name, value in feed.items() if name in self.input_names
        }
        return list(self.session.run(None, wanted))


_LOCK = threading.Lock()
_SESSIONS: dict[tuple[str, int], LoadedModel] = {}


def session_for(
    model_id: str, *, threads: int = DEFAULT_THREADS, verify: bool = True
) -> LoadedModel:
    """The shared, warmed session for a model id. Loads it on first call.

    Keyed by (model_id, threads) rather than model_id alone, because two detectors that
    disagree about thread count genuinely need two sessions, and silently handing the
    second one a session configured for the first would make its latency unexplainable.
    In practice both T1 detectors take the default and share one.

    Not on the scan path. This calls `registry.resolve`, which may download, so a
    detector calls it from `warm()`.
    """
    key = (model_id, threads)
    cached = _SESSIONS.get(key)
    if cached is not None:
        return cached

    with _LOCK:
        # Checked again inside the lock: another thread may have loaded it while this
        # one waited, and building a second 279 MB session to throw away is the exact
        # waste the lock exists to prevent.
        cached = _SESSIONS.get(key)
        if cached is not None:
            return cached

        import onnxruntime as ort

        from flowx_border.models.registry import resolve

        path, spec = resolve(model_id, verify=verify)

        options = ort.SessionOptions()
        options.intra_op_num_threads = threads
        options.inter_op_num_threads = threads
        # Deterministic execution. Constraint 6 requires the same inputs to give the
        # same answer, and parallel execution mode can reorder floating point
        # reductions.
        options.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
        options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL

        # CPU only, and explicitly rather than by omission. CPU is the reference target,
        # and a provider chosen by whatever happens to be installed would make latency
        # and numerics differ between two machines running the same version. GPU is an
        # optimisation someone opts into, never something that happens to them.
        session = ort.InferenceSession(
            str(path), options, providers=["CPUExecutionProvider"]
        )

        loaded = LoadedModel(
            session=session,
            spec=spec,
            path=path,
            threads=threads,
            input_names=frozenset(i.name for i in session.get_inputs()),
        )
        _SESSIONS[key] = loaded
        return loaded


def warm(
    model_id: str, *, threads: int = DEFAULT_THREADS, tokens: int = 16
) -> LoadedModel:
    """Load if needed, then run a throwaway pass so no real scan is the slow one.

    The pass uses zeros rather than real text. It exercises the same kernels, and text
    would need a tokenizer here, which would put the tokenizer's own loading cost inside
    a function whose job is the session's.
    """
    import numpy as np

    loaded = session_for(model_id, threads=threads)
    ids = np.zeros((1, tokens), dtype=np.int64)
    loaded.run(
        {
            "input_ids": ids,
            "attention_mask": np.ones_like(ids),
            "token_type_ids": np.zeros_like(ids),
        }
    )
    return loaded


def loaded_model_ids() -> tuple[str, ...]:
    """Which models are resident. Exists so a test can prove two detectors share one."""
    with _LOCK:
        return tuple(sorted({model_id for model_id, _threads in _SESSIONS}))


def session_count() -> int:
    """How many sessions are resident, for the same reason as above."""
    with _LOCK:
        return len(_SESSIONS)


def unload_all() -> None:
    """Drop every session. For tests, and for a caller that wants the memory back.

    Not called by the library itself: the set of loaded models cannot usefully shrink
    during a process that is still scanning.
    """
    with _LOCK:
        _SESSIONS.clear()
        _TOKENIZERS.clear()


_TOKENIZERS: dict[str, Tokenizer] = {}


def tokenizer_for(model_id: str) -> Tokenizer:
    """The tokenizer that ships with a model, loaded once per process.

    Lives here beside the session cache because it is the same kind of resource and has
    the same lifetime, and because the measured cost of getting this wrong is large:
    `tokenizer.json` for an XLM-R model is 16 MB and `Tokenizer.from_file` takes 437 ms
    on the reference machine. Three detectors were calling it inside `run`, once per
    scan, which put nearly half a second of file parsing in front of a 51 ms inference
    and made every classifier miss its budget for a reason that had nothing to do with
    the model.

    From the model's own repo and revision, never a similarly-named one: character
    offsets are only correct for the tokenizer the model was trained with, and a span
    computed against a different vocabulary is wrong rather than approximate.

    A caller configures truncation and padding on the object it gets back. That is safe
    because each model id is used by one detector, apart from `piiguard`, whose two
    detectors want the same settings. It is not safe to hand the same object to two
    callers wanting different truncation, and if that ever happens the answer is a
    per-caller copy rather than a second cache.
    """
    cached = _TOKENIZERS.get(model_id)
    if cached is not None:
        return cached
    with _LOCK:
        cached = _TOKENIZERS.get(model_id)
        if cached is not None:
            return cached

        from tokenizers import Tokenizer

        from flowx_border.models.registry import companion

        loaded = Tokenizer.from_file(str(companion(model_id, "tokenizer.json")))
        _TOKENIZERS[model_id] = loaded
        return loaded
