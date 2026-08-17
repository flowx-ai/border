# SPDX-License-Identifier: Apache-2.0
"""Which weights file a local artifact directory offers, and what happens with two.

Seven of the shipped detectors are int8. `groundedness` cannot be: its int8 export
moved probabilities by 0.07591 at the p99 against the export gate's 0.05 ceiling,
which the gate calls a different model rather than a quantisation of this one, and it
refused to write a manifest. Its fp16 export changes no decisions at a p99 of 0.01288
for 21 MB more, so the loader has to accept both names.

The ambiguous case is the one worth a test. A directory keeps its refused int8 while the
fp16 that replaced it is exported beside it, which is exactly what happened to
`groundedness` on 2026-08-15, so both names present is a real state rather than a
hypothetical one. Choosing between them silently would put a file nobody chose into
`weights_sha256` in an evidence record.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest import mock

import pytest

from flowx_border.models.registry import (
    WEIGHT_NAMES,
    ModelUnavailableError,
    _weights_in,
)


def _make(onnx_dir: Path, *names: str) -> None:
    onnx_dir.mkdir(parents=True, exist_ok=True)
    for name in names:
        (onnx_dir / name).write_bytes(b"not a real graph")


def test_an_empty_directory_offers_nothing(tmp_path: Path) -> None:
    _make(tmp_path / "onnx")
    assert _weights_in(tmp_path / "onnx") is None


def test_a_missing_directory_offers_nothing(tmp_path: Path) -> None:
    assert _weights_in(tmp_path / "absent") is None


@pytest.mark.parametrize("name", WEIGHT_NAMES)
def test_either_precision_alone_is_found(tmp_path: Path, name: str) -> None:
    _make(tmp_path / "onnx", name)
    found = _weights_in(tmp_path / "onnx")
    assert found is not None
    assert found.name == name


def test_both_precisions_present_is_refused_rather_than_chosen(tmp_path: Path) -> None:
    """The loader must not pick. See the module docstring for why this state occurs."""
    _make(tmp_path / "onnx", *WEIGHT_NAMES)
    with pytest.raises(ModelUnavailableError) as caught:
        _weights_in(tmp_path / "onnx")
    message = str(caught.value)
    for name in WEIGHT_NAMES:
        assert name in message, (
            "the error has to name both files, or it is not actionable"
        )
    assert "will not choose" in message


def test_no_model_is_both_pinned_and_unpublished() -> None:
    """A model id in MODELS and in UNPUBLISHED is two contradictory claims about it.

    `resolve` checks MODELS first, so an overlapping id would load the weights while
    UNPUBLISHED went on saying they do not exist. That is not a hypothetical: on
    2026-08-16 six detectors were published to the hub and their UNPUBLISHED entries
    were left behind, each still quoting a pre-retrain score. Nothing failed, because
    nothing compared the two.
    """
    from flowx_border.models.registry import MODELS, UNPUBLISHED

    overlap = sorted(set(MODELS) & set(UNPUBLISHED))
    assert not overlap, (
        f"{', '.join(overlap)} are pinned in MODELS and also listed as unpublished. "
        "Delete the UNPUBLISHED entry when a model is published: resolve() checks "
        "MODELS first, so the note would be unreachable and silently stale."
    )


def test_every_pinned_model_names_a_distinct_repo_and_file() -> None:
    """Two entries pointing at one file means one of them attests the wrong model."""
    from flowx_border.models.registry import MODELS

    seen: dict[str, str] = {}
    for model_id, spec in MODELS.items():
        key = f"{spec.repo}@{spec.revision}/{spec.filename}"
        assert key not in seen, (
            f"{model_id} and {seen[key]} both resolve to {key}. An evidence record "
            "would name two detectors for one set of weights."
        )
        seen[key] = model_id


def test_the_trained_length_is_the_models_own_not_a_default() -> None:
    """Windowing is `trained_max_length - 2`, so a wrong value here is a wrong score.

    Two of the nine are not 96 and both would be wrong at the default. `gibberish` was
    trained at 32, so a 94-token window feeds it three times what it ever saw, and
    `topic_scope` was trained at 128. The ONNX sequence axis is dynamic on every one of
    these graphs, so nothing would have raised: the model would simply have been asked a
    question it was not trained to answer.
    """
    from flowx_border.models.registry import MODELS

    assert MODELS["gibberish"].trained_max_length == 32
    assert MODELS["topic_scope"].trained_max_length == 128
    for model_id in ("piiguard", "bias", "injection", "nsfw", "politeness", "toxicity"):
        assert MODELS[model_id].trained_max_length == 96, model_id


# --------------------------------------- the length a local artifact was trained at


def test_a_local_artifact_declares_its_own_trained_length(tmp_path: Path) -> None:
    """The bug this guards was silent, which is why it lasted.

    Every ONNX graph here has a dynamic sequence axis, so feeding a model a
    length it was never trained at raises nothing: it answers, differently.
    `_build_local_spec` never set `trained_max_length`, so a local override took
    the 96 default. `groundedness` trains at 512, and under the override its
    512-token pairs were truncated to 96. The temporal-contradiction probe read
    0.9216 truncated against 0.7681 at full length, a gap of 0.15 where the
    export gate's own p99 drift is 0.03351, so every figure recorded for that
    probe through the library before 2026-08-17 describes a truncated source.
    """
    from flowx_border.models.registry import LOCAL_DIR_ENV, local_spec_for

    folder = tmp_path / "groundedness-full"
    (folder / "onnx").mkdir(parents=True)
    (folder / "onnx" / "model.fp16.onnx").write_bytes(b"not a real graph")
    (folder / "run.json").write_text(json.dumps({"max_length": 512}), encoding="utf-8")

    with mock.patch.dict(os.environ, {LOCAL_DIR_ENV: str(tmp_path)}):
        spec = local_spec_for("groundedness")
    assert spec is not None
    assert spec.trained_max_length == 512, "the length did not come from run.json"
    assert "run.json" in spec.notes, "the notes must say where the length came from"


def test_a_local_artifact_without_run_json_uses_the_published_length(
    tmp_path: Path,
) -> None:
    """A local re-export of a published model is nearly always the same length."""
    from flowx_border.models.registry import LOCAL_DIR_ENV, MODELS, local_spec_for

    folder = tmp_path / "gibberish-full"
    (folder / "onnx").mkdir(parents=True)
    (folder / "onnx" / "model.int8.onnx").write_bytes(b"not a real graph")

    with mock.patch.dict(os.environ, {LOCAL_DIR_ENV: str(tmp_path)}):
        spec = local_spec_for("gibberish")
    assert spec is not None
    # gibberish trains at 32, the case where the 96 default would be wrong.
    assert spec.trained_max_length == MODELS["gibberish"].trained_max_length == 32


def test_an_assumed_length_says_so_in_the_notes(tmp_path: Path) -> None:
    """With nothing declaring a length, the spec has to admit it is guessing.

    An evidence record carries these notes, and "assumed" and "read from the
    artifact" are different claims about how the model was fed.

    Uses `cee-pii` rather than `groundedness`, which this test named until
    groundedness was published on 2026-08-17: an id in MODELS now takes the
    published length, so the fallback under test was no longer reachable through
    it. The id has to be one the table does not know.
    """
    from flowx_border.models.registry import (
        DEFAULT_TRAINED_MAX_LENGTH,
        LOCAL_DIR_ENV,
        local_spec_for,
    )

    folder = tmp_path / "cee-pii-full"
    (folder / "onnx").mkdir(parents=True)
    (folder / "onnx" / "model.fp16.onnx").write_bytes(b"not a real graph")

    with mock.patch.dict(os.environ, {LOCAL_DIR_ENV: str(tmp_path)}):
        spec = local_spec_for("cee-pii")
    assert spec is not None
    assert spec.trained_max_length == DEFAULT_TRAINED_MAX_LENGTH
    assert "never saw" in spec.notes, "a guessed length must be visibly a guess"
