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

from pathlib import Path

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
