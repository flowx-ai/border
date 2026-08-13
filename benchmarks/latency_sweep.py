# SPDX-License-Identifier: Apache-2.0
"""p95 latency against input length, for the pii artifact that actually ships.

Why this exists. The landing page charted a sweep taken on `flowxai/piiguard`'s
published `onnx/model.int8.onnx`: 8.53 ms at 16 tokens rising to 53.01 at 96, about
0.54 ms per token. That artifact was withdrawn on 2026-08-12, when it was measured
against its own fp32 weights for the first time and found to lose an entity entirely
on 13 of 120 texts. The re-export with the Gather-only recipe is three times the cost,
so every point on that chart understated the shipped model by roughly a factor of
three, and the budget-crossing token count derived from it was wrong in the direction
that flatters us.

A withdrawn number does not leave the documents it was written into. This script is
how it leaves them: it re-runs the same shape of sweep against the current artifact so
the chart can be redrawn from a measurement rather than adjusted by arithmetic.

Timing is `tests/test_budgets.p95`, imported rather than reimplemented. That matters
for one reason beyond consistency: it takes the best of several rounds, because
contention can only make a measurement slower and a single round landing on a
scheduler hiccup is not evidence. It also drops the inference cache between
iterations, without which every iteration after the first is a cache hit and the
sweep measures a dict lookup.

    uv run python benchmarks/latency_sweep.py

Writes docs/reference/latency_sweep.json.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tokenizers import Tokenizer

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))

#: The token lengths the old sweep used, kept so the two are comparable point for point
#: rather than only in aggregate.
TOKEN_LENGTHS = (16, 32, 64, 96)

#: Romanian, as the old sweep was, and prose rather than entities: this measures the
#: encoder pass, and a text full of PII would also measure the checksum pass.
_FILLER = (
    "Comanda a fost expediata ieri dimineata si va ajunge in trei zile lucratoare. "
    "Curierul va suna inainte de livrare la numarul din contract. "
    "Factura este atasata mesajului si termenul de plata este de treizeci de zile. "
    "Va rugam sa confirmati primirea coletului dupa ce ajunge la sediu. "
)


def _text_of_length(tokens: int, tokenizer: Tokenizer) -> str:
    """Filler prose trimmed to exactly `tokens` tokens under the model's tokenizer.

    Trimmed by token rather than by character, and asserted afterwards, because the
    whole complaint against the figures this replaces is that they were quoted without
    the input length that makes them mean anything.
    """
    repeated = _FILLER * (tokens // 8 + 2)
    ids = tokenizer.encode(repeated, add_special_tokens=False).ids[:tokens]
    text = tokenizer.decode(ids)
    got = len(tokenizer.encode(text, add_special_tokens=False).ids)
    # Decoding and re-encoding can move by a token at a word boundary. Accept one, and
    # raise rather than assert: this runs as a script, where -O would drop an assert and
    # take the length guarantee with it. The length is the point of the whole file.
    if abs(got - tokens) > 1:
        raise ValueError(f"wanted {tokens} tokens, built {got}")
    return text


#: Refuse to measure above this one-minute load average per core.
#:
#: The first run of this script produced 912 ms at 16 tokens, then 146 at 32, 226 at 64
#: and 424 at 96: a negative slope, and a 16-token reading six times the cost of a
#: 96-token one. Nothing was wrong with the code. The machine was at a load average of
#: 19 on 16 cores, running a 20B labelling job and a VM, and the sweep measured that.
#:
#: `p95` takes the best of several rounds precisely to step over contention, and it was
#: not enough, because under sustained load every round is contended and the minimum is
#: inflated too. A best-of-rounds estimator hides a spike; it cannot hide a busy
#: machine. So the guard is here rather than in the estimator.
#:
#: This is the same failure this project keeps writing down, in its cheapest form: the
#: numbers were internally consistent enough to look like data, and the only thing that
#: said otherwise was checking what else the machine was doing.
MAX_LOAD_PER_CORE = 0.4


def _refuse_if_busy() -> str | None:
    """The reason this machine cannot produce a latency figure, or None."""
    load = os.getloadavg()[0]
    cores = os.cpu_count() or 1
    per_core = load / cores
    if per_core > MAX_LOAD_PER_CORE:
        return (
            f"load average {load:.1f} over {cores} cores is {per_core:.2f} per core, "
            f"above {MAX_LOAD_PER_CORE}. A sweep on a busy machine measures the other "
            "work. Close what is running, or pass --anyway to record a figure that "
            "must not be published."
        )
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    # One thread only. The library's default is one, and the sweep exists to describe
    # what the library does rather than what the machine can do; the thread scaling
    # figures are a separate measurement with their own caveat about taking cores from
    # the host application.
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument(
        "--anyway",
        action="store_true",
        help="measure despite load, and stamp the output unpublishable",
    )
    parser.add_argument(
        "--out", type=Path, default=Path("docs/reference/latency_sweep.json")
    )
    args = parser.parse_args()

    busy = _refuse_if_busy()
    if busy and not args.anyway:
        print(f"refusing to measure: {busy}", file=sys.stderr)
        return 2

    from flowx_border.detectors.pii import PiiDetector
    from flowx_border.models.registry import ModelUnavailableError
    from test_budgets import CFG, CTX, p95  # type: ignore[import-not-found]

    detector = PiiDetector()
    try:
        detector.warm()
    except ModelUnavailableError as error:
        print(f"cannot measure, weights unavailable: {error}", file=sys.stderr)
        return 1

    from flowx_border.detectors.pii import MODEL_ID, _tokenizer
    from flowx_border.models.registry import spec_for

    spec = spec_for(MODEL_ID)
    tokenizer = _tokenizer()

    points = []
    for tokens in TOKEN_LENGTHS:
        text = _text_of_length(tokens, tokenizer)
        measured = p95(
            lambda text=text: detector.run(text, CFG, CTX),
            args.runs,
            before=detector.forget,
        )
        per_token = measured / tokens
        points.append(
            {
                "tokens": tokens,
                "p95": round(measured, 2),
                "ms_per_token": round(per_token, 3),
            }
        )
        print(f"  {tokens:3d} tokens {measured:7.2f} ms {per_token:5.3f} ms/token")

    # The slope over the whole range rather than the mean of the per-point ratios: the
    # per-point ratio carries the fixed per-call overhead, which does not scale.
    first, last = points[0], points[-1]
    slope = (last["p95"] - first["p95"]) / (last["tokens"] - first["tokens"])

    payload = {
        "artifact": f"{spec.repo}, {spec.filename}",
        "revision": spec.revision,
        "threads": 1,
        "iterations": args.runs,
        "input": "Romanian prose, no entities",
        "machine": {
            "cpu": platform.processor() or platform.machine(),
            "platform": platform.platform(),
        },
        "points": points,
        # Present and true only when the figures were taken on a machine that was too
        # busy to trust. A consumer that renders this file must check it: the point of
        # recording a bad run is to make it unusable, not to make it invisible.
        **({"unpublishable": busy} if busy else {}),
        "ms_per_token": round(slope, 3),
        "note": (
            "Measured on the Gather-only INT8 re-export, which is the artifact the "
            "library loads. It replaces a sweep taken on the withdrawn published "
            "export, which was about three times cheaper and lost an entity on 13 of "
            "120 texts."
        ),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(f"\nslope {slope:.3f} ms/token, written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
