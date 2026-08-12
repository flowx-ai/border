# SPDX-License-Identifier: Apache-2.0
"""T1. Does each sentence of a summary appear in the source it summarises?

Ported from the Guardrails Hub's `extracted_summary_sentences_match`, which asks the
same question by calling OpenAI. The question does not need a model: it is whether each
sentence of the output has a close counterpart somewhere in the source, which is a
string comparison. `repetition` already does that shape of comparison at 0.09 ms.

**This measures overlap, not entailment, and the distinction is the whole point of
reading this docstring.** A summary that paraphrases well scores badly here. A summary
that copies a sentence and inserts "not" scores perfectly. So it is a useful check on an
extractive summary, where the output is supposed to be drawn from the source, and it is
not a groundedness check.

That warning is not boilerplate. `groundedness` in this library is a cross-encoder
trained to judge support, and measuring it revealed the model had learned to recognise
its generator's paraphrase style rather than to compare a claim against a source: it
scored 0.9999 supported for a sentence against an unrelated passage in another language.
A detector that says plainly it counts shared words is worth more than one that implies
judgement it does not have. If you need entailment, this is not it, and at the time of
writing neither is anything else here.

**With no source this reports rather than passing.** `Context.sources` empty and no
`options.sources` means there is nothing to compare against, so it emits
`summary_support_unverifiable` with action `log` and finds nothing else. Reporting no
findings would be indistinguishable from a fully supported summary, which is the failure
this library refuses everywhere.
"""

from __future__ import annotations

import difflib
from typing import Final

from flowx_border.detectors.base import OUTPUT, Context, DetectorConfig
from flowx_border.detectors.multilingual import fold as fold_text
from flowx_border.detectors.multilingual import sentences
from flowx_border.types import Finding

#: How close a sentence has to be to its best match in the source to count as supported.
#: 0.75 on difflib's ratio, which is a similar setting to `repetition`'s and chosen the
#: same way:
#: high enough that a different claim does not match, low enough that reordering a
#: clause or dropping a determiner does not break the match.
DEFAULT_SIMILARITY: Final = 0.75

#: Sentences shorter than this are not checked. "Thanks." carries no claim, and a short
#: string matches something in any long source by accident.
DEFAULT_MIN_WORDS: Final = 5

#: Bounds on the comparison, because cost is sentences times source sentences. Both
#: report when they truncate rather than letting a partial comparison look complete.
DEFAULT_MAX_SENTENCES: Final = 400
DEFAULT_MAX_SOURCE_SENTENCES: Final = 1000


class SummarySupportError(ValueError):
    """A configuration this detector cannot act on."""


class SummarySupportDetector:
    """Reports a summary sentence with no close counterpart in the source."""

    id = "summary_support"
    tier = "T1"
    sides = frozenset({OUTPUT})

    def warm(self) -> None:
        """Nothing to load. The comparison is stdlib and the splitter is a regex."""

    def run(
        self,
        text: str,
        cfg: DetectorConfig,
        ctx: Context,
    ) -> list[Finding]:
        options = cfg.options
        similarity = float(options.get("similarity", DEFAULT_SIMILARITY))
        if not 0.0 < similarity <= 1.0:
            raise SummarySupportError(
                "summary_support similarity must be above 0 and at most 1. A "
                "threshold of zero would call every sentence supported by any source."
            )
        min_words = int(options.get("min_words", DEFAULT_MIN_WORDS))
        max_sentences = int(options.get("max_sentences", DEFAULT_MAX_SENTENCES))
        max_source = int(
            options.get("max_source_sentences", DEFAULT_MAX_SOURCE_SENTENCES)
        )

        supplied = tuple(str(s) for s in options.get("sources", ()) if str(s).strip())
        sources = tuple(s for s in (*ctx.sources, *supplied) if s.strip())
        if not sources:
            return [self._reported("summary_support_unverifiable")]

        out: list[Finding] = []

        # The source side, folded once. Every summary sentence is compared against all
        # of these, so folding per comparison would repeat the work by the number of
        # summary sentences.
        source_bodies: list[str] = []
        for source in sources:
            for start, end in sentences(source):
                body = fold_text(source[start:end]).text
                if len(body.split()) >= min_words:
                    source_bodies.append(body)
        if len(source_bodies) > max_source:
            out.append(self._reported("summary_support_source_truncated"))
            source_bodies = source_bodies[:max_source]
        if not source_bodies:
            # A source made only of fragments cannot support anything, and saying so is
            # different from saying the summary is unsupported.
            return [self._reported("summary_support_no_source_sentences")]

        spans = sentences(text)
        if len(spans) > max_sentences:
            out.append(self._reported("summary_support_truncated"))
            spans = spans[:max_sentences]

        matcher = difflib.SequenceMatcher(autojunk=False)
        for start, end in spans:
            body = fold_text(text[start:end]).text
            if len(body.split()) < min_words:
                continue

            best = 0.0
            matcher.set_seq2(body)
            for candidate in source_bodies:
                matcher.set_seq1(candidate)
                # real_quick_ratio and quick_ratio are cheap upper bounds, used to skip
                # a candidate that cannot beat the best found so far. Pruning against
                # `best` rather than against `similarity` matters: gating on the
                # threshold skips every candidate once the threshold is strict, which
                # leaves `best` at zero and makes the reported score meaningless.
                # Measured at a 0.95 threshold, a near copy and a sentence about sharks
                # both scored 1.0 that way.
                if matcher.real_quick_ratio() <= best:
                    continue
                if matcher.quick_ratio() <= best:
                    continue
                best = max(best, matcher.ratio())
                if best >= similarity:
                    break

            if best >= similarity:
                continue
            out.append(
                Finding(
                    detector_id=self.id,
                    tier=self.tier,
                    label="unsupported_sentence",
                    # How far the closest match fell short, so a policy threshold can
                    # act on the degree rather than only the fact. A sentence with no
                    # overlap at all scores 1.0 here, and one that nearly matched scores
                    # near zero.
                    score=round(min(1.0, max(0.0, similarity - best) / similarity), 6),
                    span=(start, end),
                    action=cfg.on_fail,
                )
            )
        return out

    def _reported(self, label: str) -> Finding:
        """A finding that says the check could not run, always as `log`.

        The caller is told rather than blocked: an absent source is a configuration gap,
        and blocking a response over one would make the detector unusable in the common
        case where a caller has no retrieval layer.
        """
        return Finding(
            detector_id=self.id,
            tier=self.tier,
            label=label,
            score=1.0,
            span=None,
            action="log",
        )
