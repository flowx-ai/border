# SPDX-License-Identifier: Apache-2.0
"""T1: did the answer give away the instructions the model was operating under?

Ported from the Guardrails Hub `detect_system_prompt_leakage` validator, which is a
good idea with an implementation that does not do what its name says.

The bug in the original, because it is the reason for the rewrite
------------------------------------------------------------------

Upstream is one line: `fuzz.ratio(output, system_prompt) > 40`. `fuzz.ratio` is a
similarity between two whole strings, normalised by their combined length. So it
measures whether the output *is* the system prompt, not whether it *contains* it. A
2000 character answer that quotes a 200 character system prompt verbatim scores about
18 and passes, while a short answer that happens to be the same length as the prompt
and shares its common words can score over 40 and fail. The check is at its weakest
exactly where leakage matters most, which is a long, helpful-looking answer with the
instructions buried in it.

That is not a tuning problem. Containment and similarity are different questions, so
this port measures containment: how much of the system prompt appears inside the
output, in word n-grams, regardless of how much other text surrounds it.

Two signals, because a leak has two shapes
------------------------------------------

`system_prompt_quoted` is the containment measure. Score is the fraction of the system
prompt's 5-word shingles that appear in the output, so 1.0 means all of it is in there
and 0.5 means half. One finding per contiguous quoted region, each carrying that same
score, because the score is a property of the leak and the spans are what a redaction
needs.

`system_prompt_announced` is a phrase match against
data/system_prompt_phrasings.yaml, in all 26 languages: a model saying "my system
prompt" or "mi è stato detto di". It exists because the containment measure cannot
catch a paraphrase, and a paraphrase is what you get when the user asks the model to
summarise its instructions rather than repeat them. It is also the only signal available
when no system prompt was supplied at all.

`leakage_unverifiable` is emitted whenever the containment check could not run, with
action `log`. Same reasoning as the identically named finding in output_leakage.py:
reporting nothing would be indistinguishable from reporting a clean output, and a check
that silently cannot do its job is the failure this library refuses everywhere else.
The phrase match still runs and is still reported alongside it, so unverifiable means
"one of the two signals was unavailable" rather than "nothing happened".

Where the system prompt comes from
----------------------------------

`ctx.metadata["system_prompt"]`, or `options.system_prompt` for a deployment whose
prompt is fixed and therefore genuinely is policy.

**Not `ctx.sources`.** That field carries the material an answer was built from, which
is what output_leakage and groundedness compare against, and an answer is *supposed* to
contain its sources. Reading a system prompt out of it would flag every correctly
grounded answer, which is a false positive on the exact behaviour the product wants.

Budget is 5 ms at p95 at the reference input: one folding pass, one alternation, and a
substring search per shingle.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Final

import yaml

from flowx_border.detectors.base import OUTPUT, Context, DetectorConfig
from flowx_border.detectors.multilingual import (
    Folded,
    find_terms,
    fold,
    fold_text,
    shingles,
)
from flowx_border.types import Finding

_DATA: Final = (
    Path(__file__).resolve().parent.parent / "data" / "system_prompt_phrasings.yaml"
)

#: Words per shingle. Five is long enough that an ordinary sentence does not collide
#: with an unrelated system prompt by chance, and short enough that a leak which
#: reorders or lightly edits the prompt still lands on most of them. Character n-grams
#: were rejected: in a language with long compounds a character n-gram mostly measures
#: the alphabet, so a threshold set in English would mean something else in Finnish.
SHINGLE_WORDS: Final = 5

#: A system prompt shorter than this is not compared. "Be concise and polite" appears
#: inside innocent answers, so a containment measure over it reports leakage for text
#: that leaked nothing. Below the floor the detector says it could not check rather
#: than reporting a match it does not believe.
MIN_PROMPT_WORDS: Final = 4

#: Scores for the two phrase strengths. See the header of the phrasings file for why
#: `weak` sits exactly on the default threshold: raising the threshold at all is the
#: documented way to switch the weak set off.
STRONG_SCORE: Final = 0.9
WEAK_SCORE: Final = 0.5


class SystemPromptDataError(RuntimeError):
    """The phrasings file is missing or unusable.

    Raised rather than defaulted to an empty list, for the reason disclosure.py gives:
    a detector that silently falls back to no phrases still returns findings from its
    other signal, so the caller sees a working detector with one signal quietly gone.
    """


@lru_cache(maxsize=1)
def load_phrasings() -> dict[str, dict[str, tuple[str, ...]]]:
    """Phrasings per language code and strength, folded, from the packaged YAML."""
    if not _DATA.exists():
        raise SystemPromptDataError(
            f"no system prompt phrasings at {_DATA}. This file ships inside the "
            "package, so its absence means a broken install rather than a "
            "configuration mistake."
        )
    try:
        raw: Any = yaml.safe_load(_DATA.read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        raise SystemPromptDataError(f"{_DATA} is not valid YAML: {error}") from error

    languages = (raw or {}).get("languages")
    if not isinstance(languages, dict) or not languages:
        raise SystemPromptDataError(f"{_DATA} has no languages section")

    out: dict[str, dict[str, tuple[str, ...]]] = {}
    for code, entry in languages.items():
        strengths: dict[str, tuple[str, ...]] = {}
        for strength in ("strong", "weak"):
            phrases = (entry or {}).get(strength) or []
            if not isinstance(phrases, list):
                raise SystemPromptDataError(
                    f"{_DATA}: languages.{code}.{strength} must be a list"
                )
            strengths[strength] = tuple(
                fold_text(str(phrase)) for phrase in phrases if str(phrase).strip()
            )
        if any(strengths.values()):
            out[str(code)] = strengths
    if not out:
        raise SystemPromptDataError(f"{_DATA} defines no phrasings")
    return out


@lru_cache(maxsize=1)
def unreviewed_languages() -> tuple[str, ...]:
    """Language codes whose phrasings no native speaker has checked.

    Exposed for the same reason disclosure.py exposes it: a coverage table that printed
    26 languages without this caveat would be presenting 26 languages as 26 verified
    languages.
    """
    raw: Any = yaml.safe_load(_DATA.read_text(encoding="utf-8"))
    languages = (raw or {}).get("languages") or {}
    return tuple(
        sorted(
            code
            for code, entry in languages.items()
            if not (entry or {}).get("reviewed")
        )
    )


def _merge(regions: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Collapse overlapping and adjacent shingle hits into contiguous regions.

    Shingles overlap by construction, so a quoted paragraph arrives as a run of
    hits one word apart. Without merging, a 40 word leak becomes 36 findings that all
    describe the same passage, and the evidence record fills with rows an auditor has
    to reassemble by hand.
    """
    if not regions:
        return []
    ordered = sorted(regions)
    merged = [ordered[0]]
    for start, end in ordered[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return merged


class SystemPromptLeakageDetector:
    """Containment against the system prompt, plus a 26-language phrase match."""

    id = "system_prompt_leakage"
    tier = "T1"
    sides = frozenset({OUTPUT})

    def warm(self) -> None:
        """Read and fold the phrasings so no scan pays for it. Idempotent."""
        load_phrasings()

    def run(self, text: str, cfg: DetectorConfig, ctx: Context) -> list[Finding]:
        haystack = fold(text)
        findings = self._announced(haystack, cfg)

        prompt = ctx.metadata.get("system_prompt") or cfg.options.get("system_prompt")
        folded_prompt = fold_text(str(prompt)) if prompt else ""

        if len(folded_prompt.split()) < MIN_PROMPT_WORDS:
            findings.append(
                Finding(
                    detector_id=self.id,
                    tier=self.tier,
                    label="leakage_unverifiable",
                    score=1.0,
                    span=None,
                    # Always log. The caller is told a signal was unavailable, and is
                    # not blocked for a configuration gap.
                    action="log",
                )
            )
            return findings

        findings.extend(self._quoted(haystack, folded_prompt, cfg))
        return findings

    def _announced(self, haystack: Folded, cfg: DetectorConfig) -> list[Finding]:
        """Phrase match, in every language unless the policy narrows it."""
        phrasings = load_phrasings()

        wanted = cfg.options.get("languages")
        if wanted:
            codes = [str(code) for code in wanted]
            unknown = sorted(set(codes) - set(phrasings))
            if unknown:
                raise SystemPromptDataError(
                    "policy asks system_prompt_leakage to check language(s) with no "
                    f"phrasings: {', '.join(unknown)}. Known: "
                    f"{', '.join(sorted(phrasings))}. Add them through "
                    "options.extra_phrasings, or the check would silently not happen "
                    "for that language."
                )
        else:
            codes = sorted(phrasings)

        extra = cfg.options.get("extra_phrasings") or []
        by_strength = {
            "strong": tuple(
                phrase for code in codes for phrase in phrasings[code]["strong"]
            )
            + tuple(fold_text(str(p)) for p in extra if str(p).strip()),
            "weak": tuple(
                phrase for code in codes for phrase in phrasings[code]["weak"]
            ),
        }

        out: list[Finding] = []
        claimed: list[tuple[int, int]] = []
        # Strong first, so that a passage matching both is reported once at the higher
        # score rather than twice at two different ones.
        for strength, score in (("strong", STRONG_SCORE), ("weak", WEAK_SCORE)):
            if score < cfg.threshold:
                continue
            for start, end, _ in find_terms(haystack, by_strength[strength]):
                if any(start >= s and end <= e for s, e in claimed):
                    continue
                claimed.append((start, end))
                out.append(
                    Finding(
                        detector_id=self.id,
                        tier=self.tier,
                        label="system_prompt_announced",
                        score=score,
                        span=(start, end),
                        action=cfg.on_fail,
                    )
                )
        return out

    def _quoted(
        self, haystack: Folded, folded_prompt: str, cfg: DetectorConfig
    ) -> list[Finding]:
        """How much of the system prompt is inside the output, and where.

        The score is the fraction of the prompt that appears, and every finding carries
        it, because "a third of the system prompt leaked" is one fact about the answer
        and the spans are several places in it. A per-region score would invite the
        reading that each region is separately a third of a leak.
        """
        grams = shingles(folded_prompt, SHINGLE_WORDS)
        if not grams:
            return []

        hits: list[tuple[int, int]] = []
        matched = 0
        for gram in grams:
            position = haystack.text.find(gram)
            if position >= 0:
                matched += 1
                hits.append((position, position + len(gram)))

        score = matched / len(grams)
        if score < cfg.threshold or not hits:
            return []

        return [
            Finding(
                detector_id=self.id,
                tier=self.tier,
                label="system_prompt_quoted",
                score=score,
                span=haystack.span(start, end),
                action=cfg.on_fail,
            )
            for start, end in _merge(hits)
        ]
