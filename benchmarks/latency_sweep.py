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
import re
import subprocess
import sys
import time
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


#: Refuse to measure below this share of idle CPU.
#:
#: The first run of this script produced 912 ms at 16 tokens, then 146 at 32, 226 at 64
#: and 424 at 96: a negative slope, and a 16-token reading six times the cost of a
#: 96-token one. Nothing was wrong with the code, and something else on the machine was
#: taking the cores.
#:
#: `p95` takes the best of several rounds precisely to step over contention, and it was
#: not enough, because under sustained load every round is contended and the minimum is
# : inflated too. A best-of-rounds estimator hides a spike; it cannot hide a busy
# machine.
#: So the guard is here rather than in the estimator.
#:
#: **Idle CPU, not load average, and the first version of this guard got that wrong.**
#: It gated on `getloadavg()[0] / cpu_count` above 0.4, which sounds equivalent and is
# : not. Measured on the machine that motivated the guard: load average 105 over 16
# cores,
#: which the old rule scored at 6.6 per core, against a CPU that `top` reported as 76
# : percent idle with 3 threads running and 1150 sleeping. macOS counts threads blocked
# in
#: uninterruptible I/O toward load, so a machine can carry a load average of 100 while
#: having most of its cores free. The old rule would have refused to measure forever on
# : exactly the machine it was written for, which is the failure mode where a safety
# check
#: becomes a thing people pass --anyway to.
#:
#: What made those first numbers bad was cores being taken, so ask about cores directly.
# : This is the same lesson as everything else in this file: a number that sounds like
# the
#: quantity you want is not the quantity you want. Load average sounds like busyness.
MIN_IDLE_CPU = 0.70


#: Read from the platform's own reporter rather than a dependency. `psutil` would be one
#: package for one number in a script that is not part of the library, and CLAUDE.md is
#: explicit that a new dependency has to buy something. This buys a subprocess instead.
def _idle_fraction() -> float | None:
    """Share of CPU currently idle, or None if this platform cannot be asked.

    `sys.platform` goes through a variable because mypy narrows the literal and then
    calls whichever branch does not match the checking host dead code.
    """
    system = sys.platform
    if system == "darwin":
        # `top -l 1` prints one sample; -n 0 suppresses the process list. The first
        # sample of `top` is cumulative since boot, so -l 2 and the second sample would
        # be the textbook read, but -l 1 with -n 0 reports the current tick on macOS and
        # costs a fifth of the time.
        out = subprocess.run(
            ["/usr/bin/top", "-l", "1", "-n", "0"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        ).stdout
        match = re.search(r"CPU usage:.*?([\d.]+)%\s+idle", out)
        return float(match.group(1)) / 100.0 if match else None

    if system.startswith("linux"):
        # /proc/stat, sampled twice and differenced. The cumulative-since-boot figure is
        # useless here for the same reason `top`'s first sample is.
        def _snapshot() -> tuple[int, int]:
            fields = [
                int(v)
                for v in Path("/proc/stat").read_text().split("\n")[0].split()[1:]
            ]
            return sum(fields), fields[3] + (fields[4] if len(fields) > 4 else 0)

        total_a, idle_a = _snapshot()
        time.sleep(IDLE_SAMPLE_SECONDS)
        total_b, idle_b = _snapshot()
        spent = total_b - total_a
        return (idle_b - idle_a) / spent if spent else None

    return None


#: How long to sample CPU state on Linux. One instantaneous reading is a coin toss on a
#: machine with bursty background work.
IDLE_SAMPLE_SECONDS = 2.0


def _refuse_if_busy() -> str | None:
    """The reason this machine cannot produce a latency figure, or None.

    Falls back to load average where idle CPU cannot be read, and names the measure it
    used: a refusal nobody can argue with is a refusal they pass --anyway to.
    """
    idle = _idle_fraction()
    if idle is None:
        load = os.getloadavg()[0]
        cores = os.cpu_count() or 1
        # Deliberately loose. This path cannot tell I/O wait from CPU demand, so it
        # catches only the egregious case rather than pretending to the precision above.
        if load / cores > 4.0:
            return (
                f"load average {load:.1f} over {cores} cores, and idle CPU cannot "
                f"be read on {sys.platform}. Load counts threads blocked on I/O, so "
                "this is a weak check. Pass --anyway if the machine is in fact quiet."
            )
        return None

    if idle < MIN_IDLE_CPU:
        return (
            f"{idle * 100:.0f} percent of CPU is idle, below the "
            f"{MIN_IDLE_CPU * 100:.0f} percent this needs. Something else is taking "
            "the cores, and a sweep taken now measures that. Close what is running, "
            "or pass --anyway to record a figure that must not be published."
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
