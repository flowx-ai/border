# SPDX-License-Identifier: Apache-2.0
"""T1: does the output have the shape the caller asked for?

Sixteen Guardrails Hub validators collapsed into one detector, the same move that
turned six into `banned_terms`. `valid_json`, `valid_html`, `valid_url`, `has_url`,
`valid_length`, `one_line`, `lowercase`, `uppercase`, `valid_choices`, `valid_range`,
`ends_with`, `regex_match`, `cucumber_expression_match`, `two_words`, `reading_time`
and `quotes_price` are sixteen packages that each hard-code one shape assertion. The
assertion is the deployer's, so here it is policy and the detector is one file.

**This one answers no security question, and that is worth saying plainly.** It is here
because the owner asked for every hub validator to have a destination, on 2026-08-11.
Nothing in it detects an attack, and a policy that runs only this detector is not doing
security. It earns its place by being the thing that stops sixteen shape validators from
becoming sixteen detectors in a catalogue that is otherwise about security and
governance.

Where the 26 languages actually bite
------------------------------------

Shape checks look language-neutral and are not. Four of these are wrong in the obvious
implementation, and each has a test:

**Length is graphemes, not code points.** `len("că")` is 2 or 3 depending on whether the
ă arrived precomposed or decomposed, so a `max_length` in code points silently means two
different limits for the same visible text. Worse for Devanagari and emoji, but Romanian
and Czech are enough to break it. Length here counts what a reader would count.

**Croatian has letters that are neither upper nor lower.** The obvious way to write a
lowercase check is "no character in it is uppercase", and that is wrong for ǅ, ǈ, ǋ and
ǲ, the titlecase digraphs Croatian uses: `"ǅ".isupper()` is False, so the obvious check
passes a string that is not lowercase. `text == text.lower()` gets it right, and that is
what this uses. Measured rather than assumed: an earlier draft of this file claimed the
Turkish dotted I broke the same check, and it does not. Across all 26 languages the two
formulations agree everywhere except the digraphs.

**Words per minute is an English number.** `reading_time` upstream hard-codes one rate.
Finnish and Hungarian pack far more meaning per word than English does, and Greek and
Bulgarian have different word lengths again, so one constant is one language's answer
applied to 26. The rate is a policy option here, its default is stated as the
English-derived figure it is, and the finding says which rate produced it.

**A URL can be spelled two ways.** An internationalised host is one URL whether written
in Unicode or punycode, which is the same point `internal_domains` makes.

Options, all optional, all off unless set
-----------------------------------------

    json: true              parses as JSON
    html: true              parses as HTML without unclosed tags
    url: "required"|"absent"
    max_length / min_length in graphemes
    max_words / min_words   two_words is max_words: 2, min_words: 2
    one_line: true
    case: "lower"|"upper"
    choices: [...]          matched on folded text
    numeric_range: [lo, hi] the whole output read as a number
    ends_with / starts_with
    regex: "..."            a full-match pattern
    max_reading_seconds     with words_per_minute, default 200

An enabled detector with no options reports `format_not_configured` at action `log`
rather than a clean scan, for the reason banned_terms gives.

Budget is 5 ms at p95 at the reference input.
"""

from __future__ import annotations

import json
import re
import unicodedata
from html.parser import HTMLParser
from typing import Any, Final

from flowx_border.detectors.base import OUTPUT, Context, DetectorConfig
from flowx_border.detectors.multilingual import fold_text
from flowx_border.types import Finding

#: Words per minute for `max_reading_seconds`. 200 is the figure the upstream
#: `reading_time` validator bakes in, and it is an English silent-reading rate. It is
#: kept as the default so a migration behaves the same, and it is an option because
#: applying one language's rate to 26 is the kind of unstated assumption this project
#: exists to avoid. A finding records the rate that produced it.
DEFAULT_WORDS_PER_MINUTE: Final = 200

#: Options that switch a check on. Anything outside this set is a policy typo, and a
#: typo that silently disabled a check is the failure this library refuses everywhere.
_KNOWN: Final[frozenset[str]] = frozenset(
    {
        "json",
        "html",
        "url",
        "max_length",
        "min_length",
        "max_words",
        "min_words",
        "one_line",
        "case",
        "choices",
        "numeric_range",
        "ends_with",
        "starts_with",
        "regex",
        "max_reading_seconds",
        "words_per_minute",
    }
)

#: A URL, permissive on the host so an internationalised name matches in either
#: spelling. Not a validator of URL correctness: this reports presence or absence, and
#: `internal_domains` is the detector that cares which host it is.
_URL: Final = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s<>\"']+", re.IGNORECASE)

_NUMBER: Final = re.compile(r"^[+-]?\d+(?:[.,]\d+)?$")


class OutputFormatError(ValueError):
    """The policy asked for a shape check that cannot be performed as written."""


def graphemes(text: str) -> int:
    """Characters as a reader would count them.

    Combining marks do not add to the count, so a Romanian string means the same length
    whether it arrived precomposed or decomposed. NFC first so that the common case is
    a single code point, then combining marks are not counted, which covers the
    decomposed spellings NFC could not compose.
    """
    return sum(
        1
        for char in unicodedata.normalize("NFC", text)
        if not unicodedata.combining(char)
    )


class _Tags(HTMLParser):
    """Counts unclosed tags, which is all `valid_html` really asserts.

    `html.parser` is deliberately forgiving, so parsing alone never fails and would make
    the check a no-op. Tracking the open-tag stack is what turns it into an assertion.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.unmatched = 0

    # Void elements never close, so they are not pushed.
    _VOID = frozenset(
        (
            "area",
            "base",
            "br",
            "col",
            "embed",
            "hr",
            "img",
            "input",
            "link",
            "meta",
            "param",
            "source",
            "track",
            "wbr",
        )
    )

    def handle_starttag(self, tag: str, attrs: object) -> None:  # noqa: ARG002
        if tag not in self._VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag in self.stack:
            while self.stack and self.stack.pop() != tag:
                self.unmatched += 1
        else:
            self.unmatched += 1


class OutputFormatDetector:
    """Policy-driven shape assertions over the output."""

    id = "output_format"
    tier = "T1"
    sides = frozenset({OUTPUT})

    def warm(self) -> None:
        """Nothing to load. The shape arrives per scan, from the policy."""

    def run(
        self,
        text: str,
        cfg: DetectorConfig,
        ctx: Context,  # noqa: ARG002 - the Detector protocol fixes this signature
    ) -> list[Finding]:
        options = cfg.options
        unknown = sorted(set(options) - _KNOWN)
        if unknown:
            raise OutputFormatError(
                f"output_format does not know the option(s) {', '.join(unknown)}. "
                f"Known: {', '.join(sorted(_KNOWN))}. An unknown option would silently "
                "check nothing, so it is rejected rather than ignored."
            )

        active = [key for key in options if key not in ("words_per_minute",)]
        if not active:
            return [self._finding("format_not_configured", cfg, action="log")]

        out: list[Finding] = []
        for label in self._failures(text, options):
            out.append(self._finding(label, cfg))
        return out

    def _finding(
        self, label: str, cfg: DetectorConfig, action: str | None = None
    ) -> Finding:
        return Finding(
            detector_id=self.id,
            tier=self.tier,
            label=label,
            # 1.0. Every check here is a fact about the string, not a judgement.
            score=1.0,
            # No span. These are assertions about the whole output, and pointing at one
            # offset would imply a place to fix, which a shape check cannot know.
            span=None,
            action=action or cfg.on_fail,
        )

    def _failures(self, text: str, options: dict[str, Any]) -> list[str]:
        out: list[str] = []
        stripped = text.strip()

        if options.get("json") and not _parses_as_json(stripped):
            out.append("not_json")

        if options.get("html") and _unclosed_tags(text):
            out.append("not_html")

        wanted_url = options.get("url")
        if wanted_url is not None:
            present = _URL.search(text) is not None
            if wanted_url == "required" and not present:
                out.append("url_missing")
            elif wanted_url == "absent" and present:
                out.append("url_present")
            elif wanted_url not in ("required", "absent"):
                raise OutputFormatError(
                    f"output_format url must be 'required' or 'absent', not "
                    f"{wanted_url!r}"
                )

        # Graphemes, not code points. See the module docstring.
        size = graphemes(text)
        if "max_length" in options and size > int(options["max_length"]):
            out.append("too_long")
        if "min_length" in options and size < int(options["min_length"]):
            out.append("too_short")

        words = stripped.split()
        if "max_words" in options and len(words) > int(options["max_words"]):
            out.append("too_many_words")
        if "min_words" in options and len(words) < int(options["min_words"]):
            out.append("too_few_words")

        if options.get("one_line") and "\n" in text.strip():
            out.append("not_one_line")

        case = options.get("case")
        if case is not None:
            out.extend(_case_failure(text, str(case)))

        choices = options.get("choices")
        if choices is not None:
            folded = {fold_text(str(choice)) for choice in choices}
            if fold_text(stripped) not in folded:
                out.append("not_a_choice")

        span = options.get("numeric_range")
        if span is not None:
            out.extend(_range_failure(stripped, span))

        suffix = options.get("ends_with")
        if suffix is not None and not fold_text(stripped).endswith(
            fold_text(str(suffix))
        ):
            out.append("wrong_suffix")

        prefix = options.get("starts_with")
        if prefix is not None and not fold_text(stripped).startswith(
            fold_text(str(prefix))
        ):
            out.append("wrong_prefix")

        pattern = options.get("regex")
        if pattern is not None:
            try:
                compiled = re.compile(str(pattern))
            except re.error as error:
                raise OutputFormatError(
                    f"output_format regex {pattern!r} does not compile: {error}"
                ) from error
            if compiled.fullmatch(stripped) is None:
                out.append("regex_mismatch")

        limit = options.get("max_reading_seconds")
        if limit is not None:
            rate = float(options.get("words_per_minute", DEFAULT_WORDS_PER_MINUTE))
            if rate <= 0:
                raise OutputFormatError(
                    "output_format words_per_minute must be above 0"
                )
            if (len(words) / rate) * 60.0 > float(limit):
                out.append("too_long_to_read")

        return out


def _parses_as_json(text: str) -> bool:
    try:
        json.loads(text)
    except (ValueError, RecursionError):
        return False
    return True


def _unclosed_tags(text: str) -> bool:
    parser = _Tags()
    parser.feed(text)
    parser.close()
    return bool(parser.stack) or parser.unmatched > 0


def _case_failure(text: str, case: str) -> list[str]:
    """Is the text already in the case the policy wants?

    Asked as `text == text.lower()` rather than "no character is uppercase", because the
    two disagree on the Croatian titlecase digraphs ǅ ǈ ǋ ǲ, which are neither upper nor
    lower. `"ǅ".isupper()` is False, so the second formulation passes a string that is
    not lowercase. Text with no cased characters equals both its own upper and its own
    lower, so a numeric answer passes either check rather than failing both.
    """
    if case == "lower":
        return [] if text == text.lower() else ["wrong_case"]
    if case == "upper":
        return [] if text == text.upper() else ["wrong_case"]
    raise OutputFormatError(
        f"output_format case must be 'lower' or 'upper', not {case!r}"
    )


def _range_failure(text: str, span: object) -> list[str]:
    if not isinstance(span, (list, tuple)) or len(span) != 2:
        raise OutputFormatError(
            "output_format numeric_range must be a two element [low, high] list"
        )
    if _NUMBER.match(text) is None:
        return ["not_a_number"]
    # A comma decimal separator is correct in most of the 26 languages, so an output
    # reading "3,5" is a number rather than a parse failure.
    value = float(text.replace(",", "."))
    low, high = float(span[0]), float(span[1])
    return [] if low <= value <= high else ["out_of_range"]
