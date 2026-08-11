# SPDX-License-Identifier: Apache-2.0
"""T1: personal data in the output that did not come from the input.

Shares piiguard with `pii`. Not a second copy of the weights, not a second session: it
calls the same `models.onnx.session_for` with the same model id, so the cache hands back
what `pii` already loaded. 279 MB twice for one model would be a straightforward waste,
and CLAUDE.md is explicit that this detector must not do it. There is a test that counts
resident sessions.

How this differs from running `pii` on the output
--------------------------------------------------

`pii` on the output side answers "is there personal data here". This answers a narrower
and more useful question: "is there personal data here that the user did not already
provide". An assistant repeating back the email address the user just typed is not a
leak. The same assistant volunteering a *different* customer's email is the thing worth
blocking, and it looks identical to the first case unless you compare.

So the comparison needs to know what the caller already had. It comes from
`Context.sources`, which is the field the caller fills with the material the answer was
built from, plus `options.known_text` for a caller who wants to pass the prompt itself.

**When there is nothing to compare against, this detector says so rather than passing.**
With no sources and no known text, it cannot tell a leak from an echo, so it emits one
`leakage_unverifiable` finding with action `log` and finds nothing else. That is
deliberate: reporting no findings would be indistinguishable from a clean output, and a
detector that silently cannot do its job is the failure mode this library refuses
everywhere else. `log` keeps it out of the verdict, so an unconfigured caller is told
rather than blocked.
"""

from __future__ import annotations

import unicodedata
from typing import Final

from flowx_border.detectors.base import OUTPUT, Context, DetectorConfig
from flowx_border.detectors.pii import MODEL_ID, PiiDetector
from flowx_border.types import Finding

#: Prefix on every entity label this detector reports, so a reader of an evidence record
#: can tell "an email was in the output" from "an email was in the output that
#: the caller never supplied".
LEAK_PREFIX: Final = "leaked_"


def _comparable(text: str) -> str:
    """Casefolded, NFKC, whitespace collapsed, for containment tests only.

    NFKC rather than NFC here, unlike the disclosure detector: this is comparing a
    model's output against source material, and a model may well emit a full-width or
    ligature form of a character the source wrote plainly. Compatibility folding makes
    those equal. Never used to produce a span.
    """
    folded = unicodedata.normalize("NFKC", text).casefold()
    return " ".join(folded.split())


class OutputLeakageDetector:
    """PII in the output that is not present in the material the caller provided."""

    id = "output_leakage"
    tier = "T1"
    sides = frozenset({OUTPUT})

    model_id: str | None = None
    model_revision: str | None = None
    weights_sha256: str | None = None

    def __init__(self, *, threads: int | None = None) -> None:
        # Composition rather than inheritance. The tagging, windowing, offset mapping
        # and run merging are all identical, and duplicating them would mean fixing the
        # email-fragmentation bug twice.
        self._pii = PiiDetector(threads=threads)

    def warm(self) -> None:
        self._pii.warm()
        self.model_id = self._pii.model_id
        self.model_revision = self._pii.model_revision
        self.weights_sha256 = self._pii.weights_sha256

    def run(self, text: str, cfg: DetectorConfig, ctx: Context) -> list[Finding]:
        known = list(ctx.sources)
        extra = cfg.options.get("known_text")
        if extra:
            known.extend([extra] if isinstance(extra, str) else [str(x) for x in extra])

        if not any(part.strip() for part in known):
            return [
                Finding(
                    detector_id=self.id,
                    tier=self.tier,
                    label="leakage_unverifiable",
                    score=1.0,
                    span=None,
                    # Always log: the caller is told the check could not run, and is not
                    # blocked for a configuration gap.
                    action="log",
                    model_id=self.model_id,
                    model_revision=self.model_revision,
                )
            ]

        haystack = _comparable(" ".join(known))

        # One inference, on the shared session. The entity spans come back exactly as
        # `pii` would report them, and the only work here is deciding which of them the
        # caller already had.
        found = self._pii.run(text, cfg, ctx)

        return [
            Finding(
                detector_id=self.id,
                tier=self.tier,
                label=f"{LEAK_PREFIX}{finding.label}",
                score=finding.score,
                span=finding.span,
                action=cfg.on_fail,
                model_id=finding.model_id,
                model_revision=finding.model_revision,
            )
            for finding in found
            if finding.span is not None
            and _comparable(text[finding.span[0] : finding.span[1]]) not in haystack
        ]

    @property
    def shares_model_with(self) -> str:
        """The model id this detector borrows. Read by the session-sharing test."""
        return MODEL_ID
