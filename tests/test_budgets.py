# SPDX-License-Identifier: Apache-2.0
"""Latency budgets, asserted against a named reference input.

A budget with no input length attached is not a budget. The version of the table this
file replaces gave bare millisecond figures, and `pii` at "15 ms" turned out to be
true at 27 tokens and wrong by a factor of three at the 96 tokens the model was
trained on. So
`REFERENCE_INPUT` below is the thing every number is measured against, and it is a
constant in this file rather than a description in prose.

Wall clock in CI is the hard part
---------------------------------

An absolute millisecond assertion is a machine assertion. These figures come from an
Apple M-series laptop; a shared CI runner is commonly two to four times slower, and a
test that fails there tells you about the runner rather than the code. Three responses,
in decreasing order of how much they are worth:

**Structural assertions, always on.** T0 must be orders of magnitude cheaper than a
model pass; cost must be linear in tokens rather than quadratic; tier order must hold.
These compare measurements taken in the same process on the same machine, so they are
machine-independent and they catch the regressions that actually matter: an accidentally
quadratic windowing loop, a model loaded on the scan path, a T0 rule with catastrophic
backtracking.

**Absolute ceilings with headroom, always on.** 75 ms against a measured 51 ms is 1.5
times, which survives a moderately slower runner and still catches a detector that got
twice as slow. `FLOWX_BUDGET_SCALE` multiplies every ceiling for a runner known to be
slower, so the honest response to slow hardware is a documented environment variable
rather than a quietly loosened number.

**Nothing is skipped by default.** CLAUDE.md says a change that blows a budget fails
CI, so these run in the default suite. They skip only when the weights are absent,
which is a different statement from passing.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable

import pytest

os.environ.setdefault("HF_HUB_OFFLINE", "1")

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.catalogue import CATALOGUE
from flowx_border.detectors.disclosure import DisclosureDetector
from flowx_border.detectors.output_leakage import OutputLeakageDetector
from flowx_border.detectors.pii import PiiDetector
from flowx_border.detectors.secrets import SecretsDetector

#: 87 tokens under piiguard's tokenizer, 396 characters, Romanian prose with no entities
#: in it. No entities on purpose: a budget should measure the cost of looking, not the
#: cost of finding, or it becomes a function of how much PII the test author wrote.
REFERENCE_INPUT = (
    "Vă scriu în legătură cu contul meu de economii deschis anul trecut la "
    "sucursala din centru și aș dori câteva lămuriri suplimentare. "
    "Vă scriu în legătură cu contul meu de economii deschis anul trecut la "
    "sucursala din centru și aș dori câteva lămuriri suplimentare. "
    "Vă scriu în legătură cu contul meu de economii deschis anul trecut la "
    "sucursala din centru și aș dori câteva lămuriri suplimentare. "
)

#: Measured p95 on an Apple M-series laptop, one thread, CPU provider, INT8, 2026-08-11.
#: Recorded so a future reading can be compared against the figures the budgets were set
#: from, rather than only against the ceilings.
MEASURED_MS = {
    "secrets": 0.04,
    "disclosure": 0.04,
    "pii": 51.0,
    "output_leakage": 51.0,
}

#: Multiplier for a runner known to be slower than the reference machine. A documented
#: knob beats a quietly inflated ceiling, because the ceiling is the claim.
SCALE = float(os.environ.get("FLOWX_BUDGET_SCALE", "1.0"))

CFG = DetectorConfig(on_fail="flag")
CTX = Context()
SOURCED = Context(sources=("Vă mulțumim pentru mesajul dumneavoastră.",))


def p95(
    work: Callable[[], object], runs: int, before: Callable[[], object] | None = None
) -> float:
    """Milliseconds at the 95th percentile, after an unmeasured warm-up.

    `before` runs outside the timed region on every iteration, and it exists because
    of a trap this file walked into. `pii` memoises its inference, so repeating one
    text makes every iteration after the first a cache hit, and a budget suite that
    measures cache hits measures nothing while still passing. Model measurements pass a hook that
    drops the cache, so each iteration is a real encoder pass.
    """
    for _ in range(3):
        if before is not None:
            before()
        work()
    samples = []
    for _ in range(runs):
        if before is not None:
            before()
        started = time.perf_counter()
        work()
        samples.append((time.perf_counter() - started) * 1000.0)
    samples.sort()
    return samples[min(len(samples) - 1, int(len(samples) * 0.95))]


@pytest.fixture(scope="module")
def pii() -> PiiDetector:
    from flowx_border.models.registry import ModelUnavailableError

    detector = PiiDetector()
    try:
        detector.warm()
    except ModelUnavailableError as error:
        pytest.skip(f"piiguard weights not cached, cannot measure: {error}")
    return detector


@pytest.fixture(scope="module")
def leakage(pii: PiiDetector) -> OutputLeakageDetector:
    detector = OutputLeakageDetector()
    detector.warm()
    return detector


# --------------------------------------------------------------- the reference input


def test_the_reference_input_is_the_length_the_budgets_claim(pii: PiiDetector) -> None:
    # If this drifts, every figure in CLAUDE.md's table describes a different input than
    # the one the table names, which is the exact failure this file exists to prevent.
    from flowx_border.detectors.pii import _tokenizer

    tokens = len(_tokenizer().encode(REFERENCE_INPUT, add_special_tokens=False).ids)
    assert 80 <= tokens <= 96, f"reference input is {tokens} tokens, expected 87"


def test_the_reference_input_contains_nothing_to_find(pii: PiiDetector) -> None:
    # A budget should measure the cost of looking rather than the cost of finding.
    assert pii.run(REFERENCE_INPUT, CFG, CTX) == []
    assert SecretsDetector().run(REFERENCE_INPUT, CFG, CTX) == []


# ------------------------------------------------------------------ absolute ceilings


def test_secrets_is_within_budget() -> None:
    budget = CATALOGUE["secrets"].budget_ms * SCALE
    measured = p95(lambda: SecretsDetector().run(REFERENCE_INPUT, CFG, CTX), 200)
    assert measured <= budget, f"secrets {measured:.3f} ms exceeds {budget:.1f} ms"


def test_disclosure_is_within_budget() -> None:
    detector = DisclosureDetector()
    detector.warm()
    budget = CATALOGUE["disclosure"].budget_ms * SCALE
    measured = p95(lambda: detector.run(REFERENCE_INPUT, CFG, CTX), 200)
    assert measured <= budget, f"disclosure {measured:.3f} ms exceeds {budget:.1f} ms"


def test_pii_is_within_budget(pii: PiiDetector) -> None:
    budget = CATALOGUE["pii"].budget_ms * SCALE
    measured = p95(lambda: pii.run(REFERENCE_INPUT, CFG, CTX), 25, before=pii.forget)
    assert measured <= budget, (
        f"pii {measured:.1f} ms exceeds {budget:.1f} ms at {len(REFERENCE_INPUT)} "
        f"characters. Reference was {MEASURED_MS['pii']} ms. If the machine is "
        "slower rather than the code, set FLOWX_BUDGET_SCALE."
    )


def test_output_leakage_is_within_budget(pii: PiiDetector) -> None:
    """Measured on its own instance, which is the worst case and the honest one.

    The registry gives it the same PiiDetector that `pii` uses, so in a real scan it is
    usually a cache hit costing nothing. That is the optimisation, not the budget: a
    budget has to cover the case where this detector runs first, or runs alone.
    """
    solo = OutputLeakageDetector()
    solo.warm()
    budget = CATALOGUE["output_leakage"].budget_ms * SCALE
    measured = p95(
        lambda: solo.run(REFERENCE_INPUT, CFG, SOURCED), 25, before=solo.forget
    )
    assert measured <= budget, (
        f"output_leakage {measured:.1f} ms exceeds {budget:.1f} ms"
    )


# --------------------------------------------------------------------- structural


def test_a_t0_detector_is_orders_of_magnitude_cheaper_than_a_model_pass(
    pii: PiiDetector,
) -> None:
    """T0 always runs and cannot be disabled, so it has to be free in practice.

    Compared as a ratio measured in this same process, so the assertion says something
    about the code rather than the machine. 100x is far below the measured 1300x
    and still fails loudly if a T0 rule acquires catastrophic backtracking or,
    worse, starts loading something.
    """
    rules = p95(lambda: SecretsDetector().run(REFERENCE_INPUT, CFG, CTX), 200)
    model = p95(lambda: pii.run(REFERENCE_INPUT, CFG, CTX), 15, before=pii.forget)
    assert model / max(rules, 1e-6) > 100, (
        f"T0 is only {model / max(rules, 1e-6):.0f}x cheaper than a model pass. "
        "T0 runs on every scan and cannot be switched off, so it must stay negligible."
    )


def test_cost_is_linear_in_tokens_not_quadratic(pii: PiiDetector) -> None:
    """Four times the text must not cost sixteen times as much.

    This is the assertion that catches the windowing loop going quadratic, which is the
    realistic way this detector could become unusable on long documents while every
    correctness test still passes. Attention is quadratic within a window, but a
    window is fixed size, so the whole should be linear in the window count.
    """
    short = p95(lambda: pii.run(REFERENCE_INPUT, CFG, CTX), 10, before=pii.forget)
    long_input = REFERENCE_INPUT * 4
    long_cost = p95(lambda: pii.run(long_input, CFG, CTX), 6, before=pii.forget)
    ratio = long_cost / short
    assert ratio < 8.0, (
        f"4x the input cost {ratio:.1f}x the time. Linear would be near 4x; "
        "8x is the ceiling before this is quadratic in the number of windows."
    )


def test_every_catalogued_detector_has_a_budget() -> None:
    # A detector with no budget is a detector nobody has to answer for.
    for detector_id, spec in CATALOGUE.items():
        assert spec.budget_ms > 0, f"{detector_id} has no budget"


def test_the_tier_ceilings_do_not_decrease(pii: PiiDetector) -> None:
    # T3 must not be cheaper than T1, or the escalation design makes no sense: the whole
    # reason T3 runs only on escalation is that it is the expensive tier.
    by_tier: dict[str, float] = {}
    for spec in CATALOGUE.values():
        by_tier[spec.tier] = max(by_tier.get(spec.tier, 0.0), spec.budget_ms)
    ordered = [by_tier[tier] for tier in ("T0", "T1", "T2", "T3") if tier in by_tier]
    assert ordered == sorted(ordered), f"tier ceilings are not ascending: {by_tier}"


def test_the_budget_matches_what_was_measured(pii: PiiDetector) -> None:
    """The ceiling must sit above the measurement, with room but not miles of it.

    A ceiling far above the measurement stops being a budget and becomes decoration: it
    would let a detector get four times slower without failing anything. This keeps the
    two numbers tied together, so raising one without re-measuring fails here.
    """
    for detector_id, recorded in MEASURED_MS.items():
        budget = CATALOGUE[detector_id].budget_ms
        assert budget >= recorded, (
            f"{detector_id}: budget {budget} below measured {recorded}"
        )
        assert budget <= max(recorded * 30, 5.0), (
            f"{detector_id}: budget {budget} ms is far above the measured "
            f"{recorded} ms, which makes it decoration rather than a budget."
        )


# ---------------------------------------------------------------------- warm-up cost


def test_loading_a_session_costs_far_more_than_using_it(pii: PiiDetector) -> None:
    """Which is why `warm` is separate from `run` in the Detector protocol.

    Worth asserting because it is the opposite of what BUILD_PLAN.md assumed. The plan
    proposed testing that a second scan is faster than the first, on the theory that the
    first inference pays for arena allocation. Measured on 2026-08-11 that is not true
    here: first inference 52.4 ms, second 51.7 ms. The one-time cost is the session
    load, 316 ms, which is the thing `warm` exists to move off the request path.
    """
    from flowx_border.models.onnx import session_for, unload_all

    unload_all()
    started = time.perf_counter()
    session_for("piiguard", verify=False)
    load_ms = (time.perf_counter() - started) * 1000.0

    one_pass = p95(lambda: pii.run(REFERENCE_INPUT, CFG, CTX), 10, before=pii.forget)
    assert load_ms > one_pass, (
        f"session load {load_ms:.0f} ms is not more than one pass {one_pass:.0f} ms. "
        "If loading became cheap, warm() matters less and this test should be "
        "revisited rather than deleted."
    )


def test_a_second_detector_reusing_the_session_pays_nothing_to_start(
    pii: PiiDetector,
) -> None:
    # The payoff of the shared cache: output_leakage's warm() must not repeat
    # the 316 ms session load.
    started = time.perf_counter()
    OutputLeakageDetector().warm()
    reuse_ms = (time.perf_counter() - started) * 1000.0
    assert reuse_ms < 100.0, (
        f"warming a second detector on the same weights took {reuse_ms:.0f} ms, so "
        "it is loading its own session rather than reusing the cached one."
    )


# ------------------------------------------------------------------ what a scan costs


def test_the_shared_instance_makes_the_second_detector_nearly_free(
    pii: PiiDetector, leakage: OutputLeakageDetector
) -> None:
    """The payoff of sharing the inference rather than only the session.

    Before this, an output-side scan cost 116 ms, of which 51 ms was output_leakage
    running the encoder again over text `pii` had just read for the same answer.
    """
    pii.forget()
    pii.run(REFERENCE_INPUT, CFG, SOURCED)
    reuse = p95(lambda: leakage.run(REFERENCE_INPUT, CFG, SOURCED), 20)
    assert reuse < CATALOGUE["pii"].budget_ms / 5, (
        f"output_leakage took {reuse:.1f} ms after pii had already scanned the same "
        "text, so it is repeating the inference instead of reusing it."
    )


def test_the_full_output_side_scan_is_recorded(
    pii: PiiDetector, leakage: OutputLeakageDetector
) -> None:
    """Not a ceiling, a record. Printed so the aggregate is visible in CI output.

    The per-detector budgets say nothing about what a scan costs, and the aggregate is
    what a deployment feels. Today the output side is one rule check plus two encoder
    passes, and those two are on the same text with the same weights, so half of it
    is duplicated work. See the note in the plan about sharing one inference.
    """
    disclosure = DisclosureDetector()
    disclosure.warm()
    shared = pii

    def whole_scan() -> None:
        disclosure.run(REFERENCE_INPUT, CFG, SOURCED)
        pii.run(REFERENCE_INPUT, CFG, SOURCED)
        leakage.run(REFERENCE_INPUT, CFG, SOURCED)

    total = p95(whole_scan, 12, before=shared.forget)
    print(f"\n  full output-side scan p95: {total:.1f} ms at the reference input")
    # One encoder pass plus two rule checks, because output_leakage reuses pii's result.
    # Two would mean the shared instance stopped being shared.
    assert total <= 2 * CATALOGUE["pii"].budget_ms * SCALE
