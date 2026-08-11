# SPDX-License-Identifier: Apache-2.0
"""T0: characters that are in the text but not on the screen.

The gap `docs/migrating-from-llm-guard.md` has been naming since the llm-guard adapter
landed, under `InvisibleText`. Half of it was already closed:
`detectors/multilingual.py` drops these characters before matching, so they cannot be
used to slip a banned term past `banned_terms`. This is the other half, and it is the
half that matters more: reporting that they are there at all.

Why this is T0 rather than something a policy switches off
-----------------------------------------------------------

Two of the four categories below are unambiguous in this library specifically, and the
reason is the language list. All 26 supported languages are written left to right:
Latin, Greek and Cyrillic script, with Maltese in Latin and no right-to-left language in
the set at all. A bidirectional override therefore has no typographic purpose in any
text this library claims to support. In a project that supported Arabic or Hebrew this
would be a judgement call; here it is not.

Tag characters are the same shape of argument. They were deprecated for language tagging
in Unicode 3.1, nothing renders them, and their current use in the wild is smuggling
instructions past a human reader and into a model.

So the detector is T0 and cannot be disabled. The escape hatch for a deployment that
wants to know without acting is `on_fail: log`, which keeps it out of the verdict. The
two categories that do have legitimate uses are handled by not reporting them by
default, rather than by making the whole detector optional.

The four categories
-------------------

`bidi_control`
    U+202A to U+202E and U+2066 to U+2069. This is Trojan Source: an override makes text
    render in a different order from the order it is stored in, so a reviewer approves
    one thing and a machine reads another. Reported by default.

`tag_characters`
    U+E0000 to U+E007F. Each one mirrors an ASCII character and none of them renders, so
    a whole English sentence can be written in them and pasted into a prompt where no
    human sees it. This is the current shape of invisible prompt injection. Reported by
    default, and it is the reason to run this detector on the input side.

`zero_width`
    U+200B, U+200C, U+200D, U+2060, U+FEFF. Filter evasion and text fingerprinting.
    Reported by default, with one exemption: a zero-width joiner between two pictographs
    is an emoji sequence, and a family emoji is not an attack. See `_is_emoji_joiner`.

`soft_hyphen`
    U+00AD. Not reported by default. It is real typography, it appears in German and
    Hungarian text set by anything that hyphenates, and reporting it would put a finding
    on ordinary output. A policy that wants it adds it to `categories`.

Options
-------

    categories:       which to report, default the three above that are on
    allow_emoji_zwj:  bool, default true

Budget is 5 ms at p95: one pass over the string, no regular expressions.
"""

from __future__ import annotations

from typing import Final

from flowx_border.detectors.base import INPUT, OUTPUT, Context, DetectorConfig
from flowx_border.types import Finding

#: Character to category. A dict rather than ranges for everything except the tag block,
#: because the set is small, explicit is checkable, and a lookup per character is what
#: keeps this a single linear pass.
_BIDI: Final[frozenset[str]] = frozenset("‪‫‬‭‮⁦⁧⁨⁩")
_ZERO_WIDTH: Final[frozenset[str]] = frozenset("​‌‍⁠﻿")
_SOFT_HYPHEN: Final[str] = "­"

#: The deprecated tag block. Every code point mirrors an ASCII character and none of
#: them renders.
_TAG_START: Final = 0xE0000
_TAG_END: Final = 0xE007F

BIDI_CONTROL: Final = "bidi_control"
TAG_CHARACTERS: Final = "tag_characters"
ZERO_WIDTH: Final = "zero_width"
SOFT_HYPHEN: Final = "soft_hyphen"

ALL_CATEGORIES: Final[tuple[str, ...]] = (
    BIDI_CONTROL,
    TAG_CHARACTERS,
    ZERO_WIDTH,
    SOFT_HYPHEN,
)

#: On unless a policy says otherwise. `soft_hyphen` is absent because it is ordinary
#: typography in several of the 26 and reporting it would put a finding on text nobody
#: did anything wrong to.
DEFAULT_CATEGORIES: Final[tuple[str, ...]] = (
    BIDI_CONTROL,
    TAG_CHARACTERS,
    ZERO_WIDTH,
)

#: Ranges that count as a pictograph for the emoji-joiner exemption. Deliberately broad:
#: the cost of being too generous is missing a zero-width joiner between two emoji,
#: which is the case being exempted anyway, and the cost of being too narrow is a
#: finding on every family emoji a product emits.
_PICTOGRAPH_RANGES: Final[tuple[tuple[int, int], ...]] = (
    (0x1F000, 0x1FAFF),
    (0x2600, 0x27BF),
    (0x2B00, 0x2BFF),
    (0xFE0F, 0xFE0F),  # variation selector 16, which follows many emoji
    (0x1F1E6, 0x1F1FF),  # regional indicators
)


class InvisibleTextError(ValueError):
    """The policy asked for a category that does not exist."""


def _is_pictograph(char: str) -> bool:
    code = ord(char)
    return any(low <= code <= high for low, high in _PICTOGRAPH_RANGES)


def _is_emoji_joiner(text: str, index: int) -> bool:
    """Whether the zero-width joiner at `index` is holding an emoji sequence together.

    A family emoji is three pictographs joined by two of these. Reporting it would put a
    finding on ordinary output from any product whose model uses emoji, which is most of
    them, and a detector that fires on ordinary output gets switched off.
    """
    if text[index] != "‍":
        return False
    before = index - 1
    after = index + 1
    if before < 0 or after >= len(text):
        return False
    return _is_pictograph(text[before]) and _is_pictograph(text[after])


def category_of(char: str) -> str | None:
    """Which category a character falls in, or None if it is ordinary text."""
    if char in _BIDI:
        return BIDI_CONTROL
    if _TAG_START <= ord(char) <= _TAG_END:
        return TAG_CHARACTERS
    if char in _ZERO_WIDTH:
        return ZERO_WIDTH
    if char == _SOFT_HYPHEN:
        return SOFT_HYPHEN
    return None


def decode_tag_characters(text: str) -> str:
    """The ASCII a run of tag characters stands for.

    Exposed because it is what makes a `tag_characters` finding actionable. The finding
    itself never carries it: an evidence record holds hashes, not text, and the decoded
    form of smuggled text is still text. A caller investigating an incident has the
    original and can call this.
    """
    return "".join(
        chr(ord(char) - _TAG_START)
        for char in text
        if _TAG_START <= ord(char) <= _TAG_END
    )


class InvisibleTextDetector:
    """Reports characters that are present in the text and absent from the screen."""

    id = "invisible_text"
    tier = "T0"
    sides = frozenset({INPUT, OUTPUT})

    def warm(self) -> None:
        """Nothing to load. The tables are module constants, so this is a no-op."""

    def run(
        self,
        text: str,
        cfg: DetectorConfig,
        ctx: Context,  # noqa: ARG002 - the Detector protocol fixes this signature
    ) -> list[Finding]:
        wanted = self._categories(cfg)
        allow_emoji = bool(cfg.options.get("allow_emoji_zwj", True))

        # Consecutive characters of one category become one finding. Smuggled text is a
        # run of hundreds of tag characters, and reporting each separately would put
        # hundreds of rows in an evidence record describing one payload.
        out: list[Finding] = []
        run_category: str | None = None
        run_start = 0

        for index, char in enumerate(text):
            found = category_of(char)
            if found is not None and found not in wanted:
                found = None
            if found == ZERO_WIDTH and allow_emoji and _is_emoji_joiner(text, index):
                found = None

            if found != run_category:
                if run_category is not None:
                    out.append(self._finding(run_category, run_start, index, cfg))
                run_category = found
                run_start = index

        if run_category is not None:
            out.append(self._finding(run_category, run_start, len(text), cfg))
        return out

    def _categories(self, cfg: DetectorConfig) -> frozenset[str]:
        raw = cfg.options.get("categories", DEFAULT_CATEGORIES)
        if isinstance(raw, str):
            raw = [raw]
        wanted = [str(name).strip().lower() for name in raw]
        unknown = sorted(set(wanted) - set(ALL_CATEGORIES))
        if unknown:
            raise InvisibleTextError(
                f"invisible_text does not know the category/categories "
                f"{', '.join(unknown)}. Known: {', '.join(ALL_CATEGORIES)}. An unknown "
                "name would silently report nothing for it, so it is rejected."
            )
        return frozenset(wanted)

    def _finding(
        self, label: str, start: int, end: int, cfg: DetectorConfig
    ) -> Finding:
        return Finding(
            detector_id=self.id,
            tier=self.tier,
            label=label,
            # 1.0. The character is there or it is not.
            score=1.0,
            # A span, because these are exactly the characters worth removing.
            # Worth knowing what that produces: the engine substitutes a typed
            # placeholder rather than deleting, so a redacted payload reads
            # `What is my balance?[TAG_CHARACTERS]`. The invisible becomes visible,
            # which is the opposite of what "redact" does everywhere else in this
            # library and is the right outcome here: a reader who sees the placeholder
            # knows something was carried in the text that they could not see, and
            # silent deletion would leave them with no way to tell.
            span=(start, end),
            action=cfg.on_fail,
        )
