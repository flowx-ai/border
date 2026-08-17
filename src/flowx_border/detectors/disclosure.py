# SPDX-License-Identifier: Apache-2.0
"""T0: is an AI disclosure present in the output?

The narrow claim this detector supports, in the words CONTRIBUTING.md permits: it
detects
whether a required disclosure is present in the output. It does not decide whether the
disclosure is adequate, and a match here says nothing about anyone's obligations. That
distinction is legally material, so it is repeated in the data file and in the finding
labels rather than left to the reader.

Two findings, not one
---------------------

Most detectors are silent when nothing is wrong. This one reports either way:

    disclosure_missing   nothing matched. action comes from the policy.
    disclosure_present   something matched. action is always `log`.

The positive is the point. An auditor asking "did the assistant disclose itself?" needs
the affirmative recorded, not inferred from an absence of findings, because an absence
is also what a detector that never ran produces. `log` keeps it out of the verdict: the
engine maps `log` to `allow` and does not escalate on it.

Matching
--------

Word boundaries, casefolded, whitespace collapsed. Word boundaries are not decoration: a
substring search for `ai` matches "said", "again" and "email", so a naive implementation
reports a disclosure in nearly every English text and this detector becomes a no-op that
looks like a pass.

Phrasings live in data/disclosure_phrasings.yaml, one entry per language, all 26 marked
`reviewed: false` because they were not written by native speakers. A policy adds house
wording through `options.extra_phrasings` rather than by editing the package.

Budget is 5 ms at p95. One compiled alternation per language, built once, cached.
"""

from __future__ import annotations

import re
import unicodedata
from functools import lru_cache
from pathlib import Path
from typing import Any, Final

import yaml

from flowx_border.detectors.base import OUTPUT, Context, DetectorConfig
from flowx_border.types import Finding

_DATA: Final = (
    Path(__file__).resolve().parent.parent / "data" / "disclosure_phrasings.yaml"
)

_WHITESPACE: Final = re.compile(r"\s+")


class DisclosureDataError(RuntimeError):
    """The phrasings file is missing or unusable.

    Raised rather than defaulted. A disclosure detector that silently falls back to an
    empty phrase list reports `disclosure_missing` for every output, including correctly
    disclosed ones, and the caller would read a wall of findings as a product problem
    rather than an install problem.
    """


@lru_cache(maxsize=1)
def load_phrasings() -> dict[str, tuple[str, ...]]:
    """Phrasings per language code, from the packaged YAML.

    Cached for the process. The file cannot change under a running scan, and re-reading
    it per call would put a filesystem hit inside a 5 ms budget.
    """
    if not _DATA.exists():
        raise DisclosureDataError(
            f"no disclosure phrasings at {_DATA}. This file ships inside the "
            "package, so its absence means a broken install rather than a "
            "configuration mistake."
        )
    try:
        raw: Any = yaml.safe_load(_DATA.read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        raise DisclosureDataError(f"{_DATA} is not valid YAML: {error}") from error

    languages = (raw or {}).get("languages")
    if not isinstance(languages, dict) or not languages:
        raise DisclosureDataError(f"{_DATA} has no languages section")

    out: dict[str, tuple[str, ...]] = {}
    for code, entry in languages.items():
        phrasings = (entry or {}).get("phrasings") or []
        if not isinstance(phrasings, list):
            raise DisclosureDataError(
                f"{_DATA}: languages.{code}.phrasings must be a list"
            )
        cleaned = tuple(
            normalise(str(phrase)) for phrase in phrasings if str(phrase).strip()
        )
        if cleaned:
            out[str(code)] = cleaned
    if not out:
        raise DisclosureDataError(f"{_DATA} defines no phrasings")
    return out


@lru_cache(maxsize=1)
def unreviewed_languages() -> tuple[str, ...]:
    """Language codes whose phrasings no native speaker has checked.

    Exposed so that a caller building a coverage table can print the caveat rather than
    presenting 26 languages as 26 verified languages.
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


def normalise(text: str) -> str:
    """Casefold, collapse whitespace, and normalise to NFC.

    NFC because the same Romanian or Turkish word can arrive with a precomposed or a
    decomposed diacritic depending on the platform that produced it, and two spellings
    of one word must not be two different match results.
    """
    return _WHITESPACE.sub(" ", unicodedata.normalize("NFC", text).casefold()).strip()


@lru_cache(maxsize=64)
def _compiled(phrases: tuple[str, ...]) -> re.Pattern[str]:
    """One alternation for a set of phrases, longest first.

    Longest first so that the reported span covers the fullest match: with
    `artificial intelligence` and `ai` both present, the longer phrase should win rather
    than the alternation stopping at the first alternative that fits.

    The boundaries are lookarounds rather than \\b because a phrase may start or
    end with a non-word character, and \\b before a hyphen means the opposite of
    what is wanted.
    """
    ordered = sorted(set(phrases), key=len, reverse=True)
    body = "|".join(re.escape(phrase) for phrase in ordered)
    return re.compile(rf"(?<!\w)(?:{body})(?!\w)")


class DisclosureDetector:
    """Reports whether the output carries an AI disclosure."""

    id = "disclosure"
    tier = "T0"
    sides = frozenset({OUTPUT})

    def warm(self) -> None:
        """Load and compile the phrasings, so no scan pays for it.

        Idempotent: both loads are lru_cached, and compiling an already-compiled
        alternation is a cache hit.
        """
        phrasings = load_phrasings()
        _compiled(tuple(phrase for phrases in phrasings.values() for phrase in phrases))

    def run(
        self,
        text: str,
        cfg: DetectorConfig,
        ctx: Context,  # noqa: ARG002 - the Detector protocol fixes this signature
    ) -> list[Finding]:
        options = cfg.options
        phrasings = load_phrasings()

        # A policy may narrow to the languages it actually ships in. Narrowing is a real
        # need: a product that only answers in Romanian does not want an English phrase
        # in its output to count as its disclosure.
        wanted = options.get("languages")
        if wanted:
            codes = [str(code) for code in wanted]
            unknown = sorted(set(codes) - set(phrasings))
            if unknown:
                raise DisclosureDataError(
                    f"policy asks disclosure to check language(s) with no phrasings: "
                    f"{', '.join(unknown)}. Known: {', '.join(sorted(phrasings))}. Add "
                    "them through options.extra_phrasings, or the check would silently "
                    "not happen for that language."
                )
            selected = [phrase for code in codes for phrase in phrasings[code]]
        else:
            selected = [phrase for phrases in phrasings.values() for phrase in phrases]

        extra = options.get("extra_phrasings") or []
        selected.extend(
            normalise(str(phrase)) for phrase in extra if str(phrase).strip()
        )

        # Short outputs. A policy can decide that "Yes." need not carry a
        # disclosure. The default is 0, so the check always runs unless someone
        # opts out explicitly: a silent length exemption is how a disclosure
        # requirement quietly stops applying.
        min_chars = int(options.get("min_chars", 0))
        if len(text.strip()) < min_chars:
            return []

        haystack = normalise(text)
        match = _compiled(tuple(selected)).search(haystack)

        if match is None:
            return [
                Finding(
                    detector_id=self.id,
                    tier=self.tier,
                    label="disclosure_missing",
                    # 1.0: nothing matched is a fact about the text, not a judgement.
                    score=1.0,
                    # No span. There is no offset for a thing that is not there, and
                    # pointing at the end of the text would imply that is where it
                    # should go, which is not this detector's call.
                    span=None,
                    action=cfg.on_fail,
                )
            ]

        # The span is into the normalised text, which can differ in length from the
        # original wherever whitespace was collapsed. Reporting an offset that does not
        # index the caller's string would be worse than reporting none, and this finding
        # is evidence that something is present rather than something to redact.
        return [
            Finding(
                detector_id=self.id,
                tier=self.tier,
                label="disclosure_present",
                score=1.0,
                span=None,
                # Always log, never the policy's on_fail. on_fail describes what to do
                # about a missing disclosure; applying it to a present one would block
                # outputs for complying.
                action="log",
            )
        ]
