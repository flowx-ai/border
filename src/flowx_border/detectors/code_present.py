# SPDX-License-Identifier: Apache-2.0
"""T1. Does this text contain source code?

Two llm-guard scanners, `BanCode` and `Code`, and a migrating caller loses both today.
`sql_injection` parses generated SQL and says nothing about Python in a prose answer or
a shell command in a user's question. The capability is the plainer one: is there code
here.

**The question is a rule, and the rule is a list of signals rather than a judgement.**
Each signal is reported separately with its own label, span and confidence, so a policy
decides what to do with a fenced block as against an indented line that happens to end
in a brace. Nothing is collapsed into one verdict, because a caller who bans code
outright and a caller who only wants to know want different things from the same text.

That is also the answer to the obvious false positive. Prose about programming trips any
such rule: "just call the import function" is a sentence, not code. `sql_injection` has
the same problem and this library's answer is the same both times, which is to report
what fired and let the policy decide, rather than to hide a threshold inside the
detector.

**No model.** A CodeBERT-shaped classifier would be another 151 ms encoder for a
question a regex answers in a fraction of a millisecond, and it would need a corpus of
prose-about-code in 26 languages to avoid the false positive above, which is a larger
data task than the detector is worth.

One thing to say plainly, because the catalogue entry cannot: the languages this
detector cares about are programming languages, and they are not the 26 human ones. The
26-language obligation still applies and is tested, but what it means here is that a
Python snippet is found whether the prose around it is Greek or Maltese, not that the
detector knows 26 programming languages. It knows the handful whose shapes are
unambiguous.
"""

from __future__ import annotations

import re
from typing import Any, Final, NamedTuple

from flowx_border.detectors.base import INPUT, OUTPUT, Context, DetectorConfig
from flowx_border.types import Finding


class CodePresentError(ValueError):
    """A configuration this detector cannot act on."""


class Signal(NamedTuple):
    """One shape that means code, and how much it means it."""

    label: str
    pattern: re.Pattern[str]
    #: Reported as the finding's score. Not a probability and not calibrated against a
    #: corpus: it is a stated ordering between shapes, so that a policy can act on a
    #: fenced block without acting on a line that ends in a semicolon. Anything that
    #: claimed to be calibrated would need the corpus this detector exists to avoid.
    confidence: float


#: Ordered strongest first, which is the order findings come back in.
#: Every pattern here is a shape that ordinary prose does not have. The judgement in
#: each case is about the false positive rather than the true one: `def ` alone appears
#: in French and Romanian prose, so the pattern requires the parenthesis and the colon
#: that make it a definition.
SIGNALS: Final[tuple[Signal, ...]] = (
    # A fence is a deliberate act by whoever wrote the text. Nothing else in prose looks
    # like it, so this is the one signal that is close to certain.
    Signal("code_fence", re.compile(r"^[ \t]*(?:```|~~~)", re.MULTILINE), 1.0),
    Signal("code_shebang", re.compile(r"^#![ \t]*/\S+"), 0.95),
    # Definition and import shapes, each requiring the punctuation that separates the
    # construct from a sentence containing the same word.
    Signal(
        "code_definition",
        re.compile(
            r"^[ \t]*(?:"
            r"def\s+\w+\s*\(|"
            r"(?:async\s+)?function\s+\w*\s*\(|"
            r"(?:public|private|protected)\s+(?:static\s+)?[\w<>\[\]]+\s+\w+\s*\(|"
            r"class\s+\w+\s*[:({]|"
            r"fn\s+\w+\s*\(|"
            r"func\s+\w+\s*\("
            r")",
            re.MULTILINE,
        ),
        0.9,
    ),
    Signal(
        "code_import",
        re.compile(
            r"^[ \t]*(?:"
            r"import\s+[\w.]+(?:\s*;)?\s*$|"
            r"from\s+[\w.]+\s+import\s+|"
            r"#include\s*[<\"]|"
            r"using\s+[\w.]+\s*;|"
            r"require\s*\(\s*['\"]|"
            r"package\s+[\w.]+\s*;?\s*$"
            r")",
            re.MULTILINE,
        ),
        0.85,
    ),
    # An opening tag for a language whose delimiter is unambiguous.
    Signal("code_script_tag", re.compile(r"<\?php|<script[\s>]|<%[=@]?", re.I), 0.85),
    # A prompt or an invocation that only appears in a shell transcript.
    Signal(
        "code_shell",
        re.compile(
            r"(?:^|\n)[ \t]*(?:\$|>|#)\s+"
            r"(?:sudo|apt|apt-get|yum|brew|npm|pip3?|uv|cargo|go|git|curl|wget|"
            r"docker|kubectl|make|chmod|chown|systemctl|ssh|scp)\s+\S",
        ),
        0.8,
    ),
)

#: The weakest signal, and the only one that is off unless a policy asks for it.
#: Off by default because it is the one that fires on things that are not code: a table
#: of figures, a citation list, a URL with query parameters. The others are shapes prose
#: does not have; this one is a measurement of how much punctuation a line carries, and
#: prose sometimes carries a lot. A caller who wants recall over precision switches it
#: on and gets told what fired.
DENSITY_LABEL: Final = "code_dense_line"
DENSITY_CONFIDENCE: Final = 0.4
DEFAULT_MIN_DENSITY: Final = 0.28
DEFAULT_MIN_DENSE_LENGTH: Final = 24
_DENSE_PUNCTUATION: Final = frozenset("{}[]()<>;=+*/%&|!~^:.,\"'`_$#@\\")

#: Bounds the work, because every signal is scanned over the whole text. Reported when
#: it truncates rather than letting a partial scan look complete.
DEFAULT_MAX_CHARS: Final = 200_000
TRUNCATED_LABEL: Final = "code_present_truncated"


def _density(line: str) -> float:
    """The share of a line's non-space characters that are code punctuation."""
    body = [character for character in line if not character.isspace()]
    if not body:
        return 0.0
    return sum(1 for character in body if character in _DENSE_PUNCTUATION) / len(body)


class CodePresentDetector:
    """Reports each shape in the text that means source code."""

    id = "code_present"
    tier = "T1"
    sides = frozenset({INPUT, OUTPUT})

    def warm(self) -> None:
        """Nothing to load. Every pattern is compiled at import."""

    def run(
        self,
        text: str,
        cfg: DetectorConfig,
        ctx: Context,  # noqa: ARG002 - the Detector protocol fixes this signature
    ) -> list[Finding]:
        options = cfg.options
        max_chars = int(options.get("max_chars", DEFAULT_MAX_CHARS))
        min_confidence = float(options.get("min_confidence", 0.0))
        if not 0.0 <= min_confidence <= 1.0:
            raise CodePresentError(
                "code_present min_confidence must be between 0 and 1. It filters the "
                "signals below it rather than scaling them."
            )
        wanted = options.get("signals")
        if wanted is not None:
            names = {str(name) for name in wanted}
            known = {signal.label for signal in SIGNALS} | {DENSITY_LABEL}
            unknown = sorted(names - known)
            if unknown:
                raise CodePresentError(
                    f"code_present was configured with unknown signals {unknown}. "
                    f"Known signals are {sorted(known)}. A misspelled signal would "
                    "silently switch a check off, which is worse than refusing here."
                )
        else:
            names = None

        out: list[Finding] = []
        if len(text) > max_chars:
            out.append(
                Finding(
                    detector_id=self.id,
                    tier=self.tier,
                    label=TRUNCATED_LABEL,
                    score=1.0,
                    span=None,
                    action="log",
                )
            )
            text = text[:max_chars]

        for signal in SIGNALS:
            if names is not None and signal.label not in names:
                continue
            if signal.confidence < min_confidence:
                continue
            match = signal.pattern.search(text)
            if match is None:
                continue
            out.append(
                Finding(
                    detector_id=self.id,
                    tier=self.tier,
                    label=signal.label,
                    score=signal.confidence,
                    span=(match.start(), match.end()),
                    action=cfg.on_fail,
                )
            )

        density_on = (
            DENSITY_LABEL in names
            if names is not None
            else bool(options.get("punctuation_density", False))
        )
        if density_on and min_confidence <= DENSITY_CONFIDENCE:
            finding = self._dense_line(text, options, cfg)
            if finding is not None:
                out.append(finding)
        return out

    def _dense_line(
        self,
        text: str,
        options: dict[str, Any],
        cfg: DetectorConfig,
    ) -> Finding | None:
        """The first line whose punctuation share clears the floor, if any."""
        floor = float(options.get("min_density", DEFAULT_MIN_DENSITY))
        shortest = int(options.get("min_dense_length", DEFAULT_MIN_DENSE_LENGTH))
        offset = 0
        for line in text.splitlines(keepends=True):
            stripped = line.strip()
            if len(stripped) >= shortest and _density(stripped) >= floor:
                start = offset + line.index(stripped)
                return Finding(
                    detector_id=self.id,
                    tier=self.tier,
                    label=DENSITY_LABEL,
                    score=DENSITY_CONFIDENCE,
                    span=(start, start + len(stripped)),
                    action=cfg.on_fail,
                )
            offset += len(line)
        return None
