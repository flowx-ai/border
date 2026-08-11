# SPDX-License-Identifier: Apache-2.0
"""T1: the same sentence, said twice.

Ports the Guardrails Hub `redundant_sentences` validator. A model that repeats itself is
a real product failure and an unusually visible one: the user reads the same claim
twice, and the second time it reads as padding rather than as an answer.

Like `output_format`, this answers no security question and says so. It is here because
it is one of the four remaining hub validators and it turned out to be portable without
a model, which is the bar the others in that group failed.

Upstream needs two dependencies; this needs none
--------------------------------------------------

`redundant_sentences` uses `thefuzz` for the comparison and `nltk` for the sentence
splitting. Neither is necessary. `difflib` is in the standard library and computes the
same kind of ratio, and the sentence splitting is in `multilingual.sentences`, which the
readability measure in `output_format` also uses.

That matters beyond tidiness: with no dependency the detector is in `CORE`, so it works
on a machine that has never installed anything beyond the base package.

Where the 26 languages come in
------------------------------

**Sentence splitting is not `[.!?]`.** The Greek question mark is U+037E, which is a
different character from the semicolon it looks exactly like, and U+0387 ano teleia ends
a clause. A splitter that knew only ASCII punctuation would read a Greek paragraph as
one sentence, and a detector that never sees two sentences never reports a repeat. The
failure is silent, which is why `multilingual.sentences` carries the Greek terminators
and has its own test.

**Comparison is over folded text.** Two sentences differing only in case, in a Romanian
diacritic spelled with a cedilla rather than a comma, or in a zero-width character, are
the same sentence said twice. Comparing raw strings would miss all three, and the third
is how a model's repetition slips past a naive check.

What counts as a repeat
-----------------------

A sentence whose similarity to an earlier one is at or above `similarity`, default 0.9.
The finding is on the later sentence, because that is the one to remove: reporting the
first would ask a caller to delete the sentence that introduced the point.

Sentences under `min_words` are ignored, default 4. "Yes." and "Thank you." repeat
legitimately, and a detector that reported them would fire on the politest answers.

Options
-------

    similarity:  0 to 1, default 0.9
    min_words:   ignore sentences shorter than this, default 4

Budget is 5 ms at p95 at the reference input. The comparison is quadratic in the number
of sentences, which is fine for an answer and stated here because it is the thing that
would go wrong on a long document: see `max_sentences`.
"""

from __future__ import annotations

from difflib import SequenceMatcher
from typing import Final

from flowx_border.detectors.base import OUTPUT, Context, DetectorConfig
from flowx_border.detectors.multilingual import fold_text, sentences
from flowx_border.types import Finding

DEFAULT_SIMILARITY: Final = 0.9

#: Sentences below this are not compared. "Yes." and "Thank you." repeat legitimately in
#: every language here, and a check that reported them would fire hardest on the most
#: polite answers.
DEFAULT_MIN_WORDS: Final = 4

#: The comparison is quadratic in the number of sentences. An answer has tens; a
#: document a caller passed by mistake can have thousands, and 4000 sentences is 8
#: million comparisons inside a scan. Past this the detector compares the first
#: `max_sentences` and reports that it stopped, rather than either taking the time or
#: silently doing less.
DEFAULT_MAX_SENTENCES: Final = 400


class RepetitionError(ValueError):
    """The policy asked for a comparison that cannot be performed as written."""


class RepetitionDetector:
    """Reports a sentence that repeats an earlier one."""

    id = "repetition"
    tier = "T1"
    sides = frozenset({OUTPUT})

    def warm(self) -> None:
        """Nothing to load. The comparison is stdlib and the splitter is a regex."""

    def run(
        self,
        text: str,
        cfg: DetectorConfig,
        ctx: Context,  # noqa: ARG002 - the Detector protocol fixes this signature
    ) -> list[Finding]:
        options = cfg.options
        similarity = float(options.get("similarity", DEFAULT_SIMILARITY))
        if not 0.0 < similarity <= 1.0:
            raise RepetitionError(
                "repetition similarity must be above 0 and at most 1. A threshold of "
                "zero would report every sentence as a repeat of the first."
            )
        min_words = int(options.get("min_words", DEFAULT_MIN_WORDS))
        max_sentences = int(options.get("max_sentences", DEFAULT_MAX_SENTENCES))

        spans = sentences(text)
        out: list[Finding] = []

        if len(spans) > max_sentences:
            # Say the comparison was partial rather than letting a truncated one look
            # complete. Same rule as `url_check_incomplete`.
            out.append(
                Finding(
                    detector_id=self.id,
                    tier=self.tier,
                    label="comparison_incomplete",
                    score=1.0,
                    span=None,
                    action="log",
                )
            )
            spans = spans[:max_sentences]

        # Folded once per sentence rather than once per comparison. With 400 sentences
        # that is 400 folds instead of 160000.
        folded = [fold_text(text[start:end]) for start, end in spans]
        keep = [
            index for index, body in enumerate(folded) if len(body.split()) >= min_words
        ]

        reported: set[int] = set()
        for position, later in enumerate(keep):
            for earlier in keep[:position]:
                if earlier in reported:
                    # A sentence already reported as a repeat is not evidence that the
                    # next one is. Three identical sentences are two repeats of the
                    # first, not three findings about each other.
                    continue
                ratio = SequenceMatcher(None, folded[earlier], folded[later]).ratio()
                if ratio >= similarity:
                    reported.add(later)
                    out.append(
                        Finding(
                            detector_id=self.id,
                            tier=self.tier,
                            label="repeated_sentence",
                            score=round(ratio, 6),
                            # The later sentence, because that is the one to remove.
                            # Reporting the first would ask a caller to delete the
                            # sentence that introduced the point.
                            span=spans[later],
                            action=cfg.on_fail,
                        )
                    )
                    break
        return out
