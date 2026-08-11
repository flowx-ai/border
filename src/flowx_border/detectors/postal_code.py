# SPDX-License-Identifier: Apache-2.0
"""T1: postal codes in an answer that cannot exist in the country the product serves.

The local half of the Guardrails Hub `valid_address` validator. That one sends the
address to Google's Address Validation API; this one answers a narrower question with no
network, no credential and no third party, which is the trade the owner chose on
2026-08-11. See docs/porting-guardrails-validators.md for why the vendor route was
declined.

What it does and does not claim
-------------------------------

It reports that a postal code is **not well formed for any country the policy names**,
and where a country publishes a range rule, that it is **outside that range**. Spain's
first two digits are a province numbered 01 to 52, so `99123` is shaped like a Spanish
code and cannot be one.

It does not claim the address exists, that the code is allocated, or that it matches the
town written beside it. Those need a postal authority's database, which is the thing
this detector exists to avoid needing. A code that passes here is well formed, and the
finding labels say `postcode_malformed` rather than anything about validity, so a reader
of an evidence record is not invited to infer more than was checked.

Keyed by country, not by language
----------------------------------

German is official in Germany, Austria, Luxembourg and Belgium, and those are four
postcode systems: five digits, four, four and four. Latvian is official in one country
and Greek in two. So `data/postal_codes.yaml` is keyed by country and the policy names
countries, while the address cues below are keyed by language, because those really are
a property of the language. Conflating the two is the obvious way to get this wrong and
it is why the file says so at the top.

The hard part is not validating, it is noticing
------------------------------------------------

`412 EUR` is four digits. So is `2026`. A detector that validated every number in an
answer would report on prices and years, and a detector that fires on ordinary output
gets switched off. So a number is only treated as a postcode when something says it is:

- an explicit country prefix, `LV-1050` or `AZ 1000`, which is unambiguous; or
- an address cue nearby, in any of the 26 languages: a word for street or for postal
  code. `Strada Lipscani 12, 010101 București` has one, `costs 412 EUR` does not.

The consequence worth stating: an address written with no cue at all is not checked, and
this detector says nothing about it. That is a miss rather than a false positive, which
is the right direction for a check a policy may set to block.

Options
-------

    countries:     required, the ISO codes the product serves. Unconfigured it reports
                   `countries_not_configured` at action `log` rather than a clean scan.
    cue_window:    characters either side of a candidate to search for a cue, default 48
    require_cue:   default true. False validates every postcode-shaped token, which is
                   only sensible when the text is a form field rather than prose.

Budget is 5 ms at p95 at the reference input.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Final, NamedTuple

import yaml

from flowx_border.detectors.base import OUTPUT, Context, DetectorConfig
from flowx_border.detectors.multilingual import compile_terms, fold_text
from flowx_border.types import Finding

_DATA: Final = Path(__file__).resolve().parent.parent / "data" / "postal_codes.yaml"

#: How far either side of a candidate to look for a cue. 48 characters covers
#: `Strada Lipscani 12, ` and a label with whitespace, without reaching the next
#: sentence.
DEFAULT_CUE_WINDOW: Final = 48


class PostalCodeDataError(RuntimeError):
    """The postal code file is missing or unusable.

    Raised rather than defaulted to an empty table, for the reason disclosure.py gives:
    a detector that silently falls back to knowing no countries reports every postcode
    as malformed, and the caller reads a wall of findings as a product problem rather
    than an install problem.
    """


class Country(NamedTuple):
    """One country's postcode rule."""

    code: str
    name: str
    pattern: re.Pattern[str]
    prefix_length: int | None
    minimum: int | None
    maximum: int | None
    excluded: frozenset[int]
    excluded_suffixes: frozenset[str]
    reviewed: bool

    def accepts(self, candidate: str) -> bool:
        """Whether this country would accept the candidate as one of its codes."""
        if self.pattern.fullmatch(candidate) is None:
            return False
        digits = re.sub(r"\D", "", candidate)
        if self.prefix_length is not None and len(digits) >= self.prefix_length:
            prefix = int(digits[: self.prefix_length])
            if self.minimum is not None and prefix < self.minimum:
                return False
            if self.maximum is not None and prefix > self.maximum:
                return False
            if prefix in self.excluded:
                return False
        if self.excluded_suffixes:
            letters = re.sub(r"[^A-Za-z]", "", candidate).upper()
            if letters and letters in self.excluded_suffixes:
                return False
        return True


@lru_cache(maxsize=1)
def load_countries() -> dict[str, Country]:
    """Every country in the packaged file, compiled once."""
    raw = _read()
    entries = raw.get("countries")
    if not isinstance(entries, dict) or not entries:
        raise PostalCodeDataError(f"{_DATA} has no countries section")

    out: dict[str, Country] = {}
    for code, entry in entries.items():
        pattern = (entry or {}).get("pattern")
        if not pattern:
            raise PostalCodeDataError(f"{_DATA}: countries.{code} has no pattern")
        ranges = (entry or {}).get("ranges") or {}
        try:
            compiled = re.compile(str(pattern))
        except re.error as error:
            raise PostalCodeDataError(
                f"{_DATA}: countries.{code} pattern does not compile: {error}"
            ) from error
        out[str(code).lower()] = Country(
            code=str(code).lower(),
            name=str((entry or {}).get("name", code)),
            pattern=compiled,
            prefix_length=ranges.get("prefix_length"),
            minimum=ranges.get("minimum"),
            maximum=ranges.get("maximum"),
            excluded=frozenset(int(value) for value in ranges.get("excluded", ())),
            excluded_suffixes=frozenset(
                str(value).upper()
                for value in (entry or {}).get("excluded_suffixes", ())
            ),
            reviewed=bool((entry or {}).get("reviewed", False)),
        )
    return out


@lru_cache(maxsize=1)
def load_cues() -> tuple[str, ...]:
    """Every address cue in every language, folded, longest first.

    Flattened across languages rather than kept per language, because a cue is evidence
    that a number is a postcode and it does not matter which language supplied it. A
    Romanian address in an English answer still says `strada`.
    """
    raw = _read()
    languages = (raw.get("cues") or {}).get("languages")
    if not isinstance(languages, dict) or not languages:
        raise PostalCodeDataError(f"{_DATA} has no cues section")
    words = {
        fold_text(str(word))
        for entry in languages.values()
        for kind in ("street", "postcode")
        for word in (entry or {}).get(kind, ())
        if str(word).strip()
    }
    return tuple(sorted(words, key=len, reverse=True))


@lru_cache(maxsize=1)
def load_suffix_cues() -> tuple[str, ...]:
    """Cues that end a compound word rather than standing alone.

    `Herengracht` is one word, and so are `Bahnhofstrasse`, `Storgatan`, `Noerregade`
    and `Mannerheimintie`. A whole-word cue matches none of them, so without this the
    detector checks nothing in the Germanic and Nordic languages, which are exactly the
    ones where a street name is written as a single token.
    """
    raw = _read()
    languages = (raw.get("suffix_cues") or {}).get("languages")
    if not isinstance(languages, dict) or not languages:
        raise PostalCodeDataError(f"{_DATA} has no suffix_cues section")
    words = {
        fold_text(str(word))
        for entry in languages.values()
        for word in entry or ()
        if str(word).strip()
    }
    return tuple(sorted(words, key=len, reverse=True))


@lru_cache(maxsize=1)
def _suffix_pattern() -> re.Pattern[str]:
    """One alternation matching a suffix cue at the end of a word.

    A right boundary only: the cue has to end the word and anything may precede it, so
    `gracht` matches `Herengracht` and not `grachten`.
    """
    body = "|".join(re.escape(cue) for cue in load_suffix_cues())
    return re.compile(rf"(?:{body})(?!\w)")


@lru_cache(maxsize=1)
def unreviewed_countries() -> tuple[str, ...]:
    """Countries whose pattern nobody has checked against a postal authority."""
    return tuple(
        sorted(
            code for code, country in load_countries().items() if not country.reviewed
        )
    )


def _read() -> dict[str, Any]:
    if not _DATA.exists():
        raise PostalCodeDataError(
            f"no postal code data at {_DATA}. This file ships inside the package, so "
            "its absence means a broken install rather than a configuration mistake."
        )
    try:
        raw: Any = yaml.safe_load(_DATA.read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        raise PostalCodeDataError(f"{_DATA} is not valid YAML: {error}") from error
    if not isinstance(raw, dict):
        raise PostalCodeDataError(f"{_DATA} is not a mapping")
    return raw


#: Postcode-shaped tokens. Broad on purpose: narrowing it here would decide which
#: countries exist, and that is the data file's job. The cue test below is what keeps
#: this from matching every number in the text.
_CANDIDATE: Final = re.compile(
    r"(?<![\w-])"
    r"(?:[A-Za-z]{1,3}[ -]?)?"  # a country or Eircode-style prefix
    r"[0-9][0-9A-Za-z]{2,6}"
    # A second block, for the codes written in two parts: `1012 AB`, `111 29`,
    # `D02 AF30`. The lookahead is what stops it swallowing the town: without it
    # `10005 Baku` is one candidate and nothing recognises it, because no country
    # issues a code ending in a four letter word. Three or more consecutive letters
    # are a word rather than the tail of a postcode.
    r"(?:[ -](?![A-Za-z]{3,})[0-9A-Za-z]{2,4})?"
    r"(?![\w-])"
)


class PostalCodeDetector:
    """Checks postal codes against the countries a policy says it serves."""

    id = "postal_code"
    tier = "T1"
    sides = frozenset({OUTPUT})

    def warm(self) -> None:
        """Read and compile the data so no scan pays for it. Idempotent."""
        load_countries()
        load_cues()
        _suffix_pattern()

    def run(
        self,
        text: str,
        cfg: DetectorConfig,
        ctx: Context,  # noqa: ARG002 - the Detector protocol fixes this signature
    ) -> list[Finding]:
        options = cfg.options
        known = load_countries()

        raw = options.get("countries") or []
        if isinstance(raw, str):
            raw = [raw]
        wanted = [str(code).strip().lower() for code in raw if str(code).strip()]

        if not wanted:
            return [
                Finding(
                    detector_id=self.id,
                    tier=self.tier,
                    label="countries_not_configured",
                    score=1.0,
                    span=None,
                    # Always log. Only the deployment knows which countries it serves,
                    # and blocking traffic over the library's own default would punish
                    # the caller for it.
                    action="log",
                )
            ]

        unknown = sorted(set(wanted) - set(known))
        if unknown:
            raise PostalCodeDataError(
                f"postal_code has no rule for country/countries {', '.join(unknown)}. "
                f"Known: {', '.join(sorted(known))}. An unknown code would match "
                "nothing and report every postcode as malformed, so it is rejected."
            )

        countries = [known[code] for code in wanted]
        window = int(options.get("cue_window", DEFAULT_CUE_WINDOW))
        require_cue = bool(options.get("require_cue", True))

        others = [country for code, country in known.items() if code not in set(wanted)]

        out: list[Finding] = []
        for match in _CANDIDATE.finditer(text):
            candidate = match.group()
            if any(country.accepts(candidate) for country in countries):
                continue

            label = self._label_for(candidate, countries, others)
            if label is None:
                continue
            if require_cue and not self._has_cue(text, match.start(), window):
                continue
            out.append(
                Finding(
                    detector_id=self.id,
                    tier=self.tier,
                    label=label,
                    score=1.0,
                    span=match.span(),
                    action=cfg.on_fail,
                )
            )
        return out

    def _label_for(
        self, candidate: str, countries: list[Country], others: list[Country]
    ) -> str | None:
        """Which of the two findings this candidate is, or neither.

        Two questions, and keeping them apart is what makes this usable. A token that
        matches a configured country's shape and fails its range rule is malformed:
        `99123` is Spanish-shaped and province 99 does not exist. A token that matches
        some other country's format completely is not malformed at all, it is a postcode
        for a country the policy does not serve, which is a different thing to tell
        somebody.

        Anything matching no country's format is not reported. That is what keeps house
        numbers out: `100` beside `1012 AB` is three digits and no country in the file
        issues a three digit code, so it is not a postcode that went wrong, it is not a
        postcode. An earlier version compared digit counts within one, which reported
        every house number in the Netherlands.
        """
        if any(
            country.pattern.fullmatch(candidate) is not None for country in countries
        ):
            # Shape matched, so `accepts` must have failed on a range or a suffix rule.
            return "postcode_malformed"
        if any(country.accepts(candidate) for country in others):
            return "postcode_wrong_country"
        return None

    def _has_cue(self, original: str, start: int, window: int) -> bool:
        """Whether an address word appears near the candidate.

        Matched on word boundaries through `compile_terms`, which is the same machinery
        `banned_terms` uses and is here for the same reason. Several cues are one or two
        letters: `c` for calle, `u` for utca, `g` for gatve, `al` for aleja. As
        substrings they appear inside ordinary words in every language, and an earlier
        version using `in` reported the year in "dated 2026" because the sentence
        contained the letter c.

        Searched over a folded slice of the original rather than by index arithmetic
        across the two, because folding changes length.
        """
        words = compile_terms(load_cues(), True)
        low = max(0, start - window)
        high = min(len(original), start + window)
        neighbourhood = fold_text(original[low:high])
        if words is not None and words.search(neighbourhood) is not None:
            return True
        return _suffix_pattern().search(neighbourhood) is not None
