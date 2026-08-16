# SPDX-License-Identifier: Apache-2.0
"""T1: which of the 26 supported languages this text is in, and whether that is allowed.

The llm-guard `Language` and `LanguageSame` scanners map here, and until this existed
the shim could only say the capability was absent. That is the migration reason. The
better reason is internal: a library claiming 26 languages could not say which one it
was looking at, and every per-language number in this repository was computed against a
label its corpus asserted rather than one measured on the text.

What it reports
---------------

`language_not_allowed` when the text is confidently in a language the policy did not
list. `language_differs_from_input` when an answer is in a different language from the
prompt that produced it, which is the `LanguageSame` question and needs `ctx.metadata`.
`language_uncertain` when the text is too short or too mixed to call.

None of those is a pass. A detector that quietly returns nothing on a five-word answer
would be reporting "allowed" for a check that never ran, which CLAUDE.md's third rule
forbids, so the uncertain case is a finding with a `log` action rather than silence.

Why the uncertain case is the interesting one
----------------------------------------------

Language identification on short text is unreliable and everybody's is. `Ok` is not
evidence of anything, `Merci` is French and Romanian and Catalan, and a Bulgarian
sentence quoting an English product name is two languages. So the detector reports a
margin, the gap between the best and second-best language, and calls anything under
`options.min_margin` uncertain rather than guessing.

The default margin was chosen against text this project's profile builder never saw,
not against a held-out slice of the corpus it was built from. That distinction is the
whole reason the number is trustworthy: a threshold tuned on the generator's own output
would agree with the generator.

What it is not
--------------

Not a translation check, not a quality check, and not a claim about any language this
library does not support. Japanese is scored against 26 profiles and comes back
uncertain rather than Japanese, because the profiles do not contain it. The finding says
`language_uncertain`, which is honest, rather than naming the closest of 26 wrong
answers.
"""

from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path
from typing import Any, Final

from flowx_border.detectors.base import INPUT, OUTPUT, Context, DetectorConfig
from flowx_border.types import Finding

_DATA: Final = (
    Path(__file__).resolve().parent.parent / "data" / "language_profiles.json"
)

#: Matches the builder in border_train/build_language_profiles.py. Any change here is a
#: change there, and a profile scored with different normalisation is a profile of
#: something else.
_DIGITS: Final = re.compile(r"\d+")
_SPACE: Final = re.compile(r"\s+")

#: Below this many characters, nothing is claimed. Not a tuned number: it is the length
#: at which trigram counts stop being a distribution and start being an anecdote. Twenty
#: characters is about three words, and three words is genuinely ambiguous across
#: related languages.
MIN_CHARACTERS: Final = 20

#: The default gap in mean log probability between the best and second-best language.
#: Measured on text outside the profile corpus; see the module docstring on why that
#: matters more than the value.
DEFAULT_MIN_MARGIN: Final = 0.12

_PROFILES: dict[str, Any] | None = None


def _load() -> dict[str, Any]:
    global _PROFILES
    if _PROFILES is None:
        if not _DATA.exists():
            raise FileNotFoundError(
                f"no language profiles at {_DATA}. This file ships inside the package; "
                "rebuild it with border_train.build_language_profiles."
            )
        _PROFILES = json.loads(_DATA.read_text(encoding="utf-8"))
    return _PROFILES


def normalise(text: str) -> str:
    """Identical to the builder's. See the note on _DIGITS."""
    text = unicodedata.normalize("NFC", text).lower()
    text = _DIGITS.sub("0", text)
    text = _SPACE.sub(" ", text).strip()
    return f" {text} "


def score_languages(text: str) -> list[tuple[str, float]]:
    """Mean log probability per language, best first.

    Mean rather than sum, so a long text and a short one are on the same scale and one
    threshold works for both. A sum would make every long text look confident.
    """
    profiles = _load()["profiles"]
    normalised = normalise(text)
    grams = [normalised[i : i + 3] for i in range(len(normalised) - 2)]
    if not grams:
        return []

    scored: list[tuple[str, float]] = []
    for code, profile in profiles.items():
        table = profile["trigrams"]
        unseen = profile["unseen_log"]
        total = 0.0
        for gram in grams:
            total += table.get(gram, unseen)
        scored.append((code, total / len(grams)))
    scored.sort(key=lambda pair: pair[1], reverse=True)
    return scored


def identify(
    text: str, min_margin: float = DEFAULT_MIN_MARGIN
) -> tuple[str | None, float]:
    """The language and the margin over the runner-up, or None when it is too close.

    Returns the margin either way, because a caller reading an evidence record should
    be able to see how close the call was rather than only what it decided.
    """
    if len(text.strip()) < MIN_CHARACTERS:
        return None, 0.0
    scored = score_languages(text)
    if len(scored) < 2:
        return None, 0.0
    margin = scored[0][1] - scored[1][1]
    if margin < min_margin:
        return None, margin
    return scored[0][0], margin


def confidence(margin: float) -> float:
    """The margin as a `Finding.score`, which the type constrains to 0.0 to 1.0.

    A margin is a gap in mean log probability and is not bounded: Bulgarian against 25
    Latin-script profiles scores 3.3, and Romanian against its neighbours scores 0.33.
    Clamping at 1.0 rather than rescaling, because everything above it is equally
    "certain" and a ratio invented to fill the range would read like a probability
    without being one.
    """
    return min(1.0, max(0.0, round(margin, 4)))


class LanguageIdDetector:
    """Character trigram language identification over the 26 supported languages."""

    id = "language_id"
    tier = "T1"
    sides = frozenset({INPUT, OUTPUT})

    def warm(self) -> None:
        """Load the profiles once, so the first scan does not pay for the file read."""
        _load()

    def run(self, text: str, cfg: DetectorConfig, ctx: Context) -> list[Finding]:
        options = cfg.options or {}
        allowed = options.get("allowed")
        min_margin = float(options.get("min_margin", DEFAULT_MIN_MARGIN))
        span = (0, len(text))
        language, margin = identify(text, min_margin)

        if language is None:
            # Not a pass. See the module docstring: silence here would report a clean
            # result for a check that could not run.
            return [
                Finding(
                    detector_id=self.id,
                    tier=self.tier,
                    label="language_uncertain",
                    score=confidence(margin),
                    span=span,
                    action="log",
                )
            ]

        # What it found, always, as its own finding.
        #
        # A label is an enum here, `^[a-z][a-z0-9_]{0,63}$`, so it cannot carry a
        # code after a colon, and that constraint is right: a reader of an evidence
        # record groups by label and free text does not group. The identification is
        # therefore a finding of its own rather than an annotation on another one, which
        # also means the record says which language was seen even when nothing was
        # configured and nothing was wrong.
        out: list[Finding] = [
            Finding(
                detector_id=self.id,
                tier=self.tier,
                label=f"language_{language}",
                score=confidence(margin),
                span=span,
                action="log",
            )
        ]

        # The Language scanner: is this one of the languages the policy permits?
        if allowed is not None and language not in {str(code) for code in allowed}:
            out.append(
                Finding(
                    detector_id=self.id,
                    tier=self.tier,
                    label="language_not_allowed",
                    score=confidence(margin),
                    span=span,
                    action=cfg.on_fail,
                )
            )

        # The LanguageSame scanner. The prompt's language has to come from the caller,
        # because a detector sees one side at a time and the engine has no memory of the
        # other. Absent, this half does not run and says so rather than reporting an
        # agreement it never checked.
        if options.get("match_input"):
            expected = ctx.metadata.get("input_language")
            if not expected:
                out.append(
                    Finding(
                        detector_id=self.id,
                        tier=self.tier,
                        label="input_language_unknown",
                        score=0.0,
                        span=span,
                        action="log",
                    )
                )
            elif expected != language:
                out.append(
                    Finding(
                        detector_id=self.id,
                        tier=self.tier,
                        label="language_differs_from_input",
                        score=confidence(margin),
                        span=span,
                        action=cfg.on_fail,
                    )
                )
        return out


__all__ = [
    "DEFAULT_MIN_MARGIN",
    "MIN_CHARACTERS",
    "LanguageIdDetector",
    "confidence",
    "identify",
    "score_languages",
]
