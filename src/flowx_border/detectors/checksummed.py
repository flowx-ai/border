# SPDX-License-Identifier: Apache-2.0
"""Card numbers and IBANs found by their own checksum, without asking the model.

Added 2026-08-12, after an export gate refused a retrain and chasing the refusal turned
up something worse than the disagreement it had reported. Measured through the detector:

| written as | the model returns | what stays in the clear |
|---|---|---|
| `4111111111111111` | `national_id` over all of it | nothing, the label is wrong |
| `4111 1111 1111 1111` | `national_id` over `4111` | twelve digits |
| `RO49 AAAA 1B31 0075 9384 0000` | `iban` from `AAAA` onward | `RO49` |

So two failures, and the second is the one that matters. A label this library gets wrong
is a wrong sentence in an evidence record; a span it gets short is an account number a
caller believes was redacted. The cause of the first is the training generator, whose
card numbers are all unspaced, so the model never saw one written the way a statement
writes it. That is a training fix and it is queued.

This module is why the leak does not have to wait for it. A card number and an IBAN both
carry a checksum, which means both can be found with no model at all, in any language
and in any presentation form. `entity_shapes.py` already had the two checks; it used
them to filter what the model said. This uses them to find what the model missed.

**It supplements the model and does not replace it.** Nothing here finds a person, a
date or a phone number, and a card from a scheme outside the table below is still the
model's to catch. What it guarantees is narrower and worth having on its own: a
Luhn-valid PAN or a mod-97-valid IBAN in the text is reported, whatever the model
thought of it.

Which way each rule fails
-------------------------

The same argument as `entity_shapes.py`, one step further along. This feeds a redactor,
so a span that is too wide costs a character of the caller's text and a span that is too
narrow is a disclosure. Every judgement below resolves that way:

- **A run is read longest-first**, so `RO49 AAAA 1B31 0075 9384 0000` beats the 24
  characters of it that also happen to validate. Two lengths of one run can both pass
  mod-97, at about one chance in 97 per candidate, and taking the longer over-redacts
  where taking the shorter would clip.
- **Every group boundary inside a run is a candidate start and a candidate end**, rather
  than one greedy match. `4111 1111 1111 1111 09 26` is eighteen digits in one run and
  no scheme issues eighteen, so a single match tests that and reports nothing.
- **A card needs its scheme, not just Luhn.** 13 to 19 digits and a passing Luhn is one
  number in ten, and a 15-digit IMEI passes it. Redacting an IMEI would be harmless;
  writing "a card number was present" into a signed record because of one is not, so the
  claim is only made for a prefix and length some scheme actually issues.

What the checksums cannot do is tell a real card from a test card, so `4111 1111 1111
1111` is reported here exactly as a live PAN would be. That is the right way round: the
alternative is a published list of test numbers that a caller could pad their data with.
"""

from __future__ import annotations

import re
from typing import Final

from flowx_border.detectors.entity_shapes import iban_ok, luhn_ok

#: The two labels this module reports. Both are `pii.ENTITY_TYPES` entries, asserted in
#: the tests rather than imported, because `pii` imports this module.
CARD: Final = "card"
IBAN: Final = "iban"

#: The score on every finding from here. 1.0 because a checksum is a fact rather than a
#: confidence, the same reason the shape gate's notes carry it. A consequence worth
#: knowing: these findings pass any threshold a policy sets, which is intended. A
#: mod-97-valid IBAN is not more or less of an IBAN depending on how strict the caller
#: is.
VERIFIED_SCORE: Final = 1.0

#: Characters that may sit between two characters of one number without ending it. One
#: only, and only with a character of the number on each side, so a full stop that ends
#: a sentence is not a separator and neither is a double space. The non-breaking and
#: fixed-width spaces are in the set because a number copied out of a statement or a PDF
#: carries them, and are spelled as escapes so they are visible in the source.
_SEPARATORS: Final = frozenset({" ", "-", ".", "\u00a0", "\u2007", "\u2009", "\u202f"})

#: The head of every IBAN: two letters for the country, two check digits.
_IBAN_HEAD: Final = re.compile(r"[A-Za-z]{2}[0-9]{2}")

#: ISO 13616 puts an IBAN between 15 and 34 characters. The per-country length is not
#: used, deliberately: a table of 78 lengths would decide where a run ends, and one
#: wrong entry there is a country whose IBANs are silently never found. mod-97 at a
#: group boundary decides instead, so a country this library has never heard of still
#: works.
_IBAN_MIN: Final = 15
_IBAN_MAX: Final = 34

#: Issuer identification ranges, as (low, high, digits in the prefix, lengths issued).
#: From the scheme specifications. The reason this table exists rather than a bare Luhn
#: check is one row below it: a 15-digit IMEI is Luhn-valid, and no scheme issues 15
#: digits behind an IMEI's reporting-body prefix.
_SCHEMES: Final[tuple[tuple[int, int, int, frozenset[int]], ...]] = (
    # Visa
    (4, 4, 1, frozenset({13, 16, 19})),
    # Mastercard, the original 51 to 55 block and the 2221 to 2720 block added in 2017
    (51, 55, 2, frozenset({16})),
    (2221, 2720, 4, frozenset({16})),
    # American Express
    (34, 34, 2, frozenset({15})),
    (37, 37, 2, frozenset({15})),
    # Discover
    (6011, 6011, 4, frozenset({16, 17, 18, 19})),
    (644, 649, 3, frozenset({16, 17, 18, 19})),
    (65, 65, 2, frozenset({16, 17, 18, 19})),
    # JCB
    (3528, 3589, 4, frozenset({16, 17, 18, 19})),
    # Diners Club
    (300, 305, 3, frozenset({14, 16, 19})),
    (3095, 3095, 4, frozenset({14, 16, 19})),
    (36, 36, 2, frozenset({14, 16, 19})),
    (38, 39, 2, frozenset({14, 16, 19})),
    # UnionPay
    (62, 62, 2, frozenset({16, 17, 18, 19})),
    # Maestro. Issued from 12 digits up, and 12 is deliberately not here: with it, the
    # thousands-separated amount `1.234.567.890.123.456` reported a card, because
    # `567.890.123.456` is twelve Luhn-valid digits behind a `56` prefix. Mastercard
    # stopped issuing Maestro in 2023, so the recall this gives up is old cards written
    # with separators, and what it buys is that a formatted number is not a card number.
    (50, 50, 2, frozenset(range(13, 20))),
    (56, 58, 2, frozenset(range(13, 20))),
)

_CARD_MIN: Final = min(min(lengths) for *_, lengths in _SCHEMES)
_CARD_MAX: Final = max(max(lengths) for *_, lengths in _SCHEMES)

#: A group span, as half-open character indices into the caller's text.
_Group = tuple[int, int]


def _is_body(character: str) -> bool:
    """Whether a character can be part of one of these numbers.

    ASCII alphanumerics only. An IBAN is defined over them, and a PAN over ASCII digits,
    so a Cyrillic or Greek letter ends a run rather than joining it. That is what keeps
    `Плащане по BG80...` from becoming one run: the words around the number are not part
    of it in any of the 26 languages.
    """
    return character.isascii() and character.isalnum()


def _runs(text: str) -> list[list[_Group]]:
    """Split the text into runs, each a list of the group spans it is made of.

    A group is a maximal stretch of body characters. Two groups belong to one run when
    exactly one separator sits between them, which is what makes `4111 1111 1111 1111`,
    `4111-1111-1111-1111` and `4111111111111111` the same run of a different shape.
    """
    runs: list[list[_Group]] = []
    current: list[_Group] = []
    index = 0
    while index < len(text):
        if not _is_body(text[index]):
            index += 1
            continue
        start = index
        while index < len(text) and _is_body(text[index]):
            index += 1
        gap = text[current[-1][1] : start] if current else ""
        if current and not (len(gap) == 1 and gap in _SEPARATORS):
            runs.append(current)
            current = []
        current.append((start, index))
    if current:
        runs.append(current)
    return runs


def _candidates(
    run: list[_Group], low: int, high: int, starts: list[int] | None = None
) -> list[tuple[int, int]]:
    """Every group subsequence of `run` holding `low` to `high` body characters.

    Longest first, then leftmost, which is the order acceptance walks. Every group is a
    candidate start as well as a candidate end, so `Ref 99 4111 1111 1111 1111` finds
    the card that does not begin where the run does. `starts` narrows that to the group
    indices a caller has already ruled in.

    Returned as text spans rather than group indices, since that is all the caller
    needs.
    """
    running = [0]
    for start, end in run:
        running.append(running[-1] + end - start)
    out: list[tuple[int, int, int]] = []
    for first in range(len(run)) if starts is None else starts:
        for last in range(first, len(run)):
            count = running[last + 1] - running[first]
            if count > high:
                break
            if count >= low:
                out.append((count, run[first][0], run[last][1]))
    out.sort(key=lambda entry: (-entry[0], entry[1]))
    return [(start, end) for _, start, end in out]


def _is_pan(digits: str) -> bool:
    """Whether a digit string is a length and prefix some scheme issues."""
    length = len(digits)
    if not _CARD_MIN <= length <= _CARD_MAX:
        return False
    return any(
        length in lengths and low <= int(digits[:width]) <= high
        for low, high, width, lengths in _SCHEMES
    )


def _one_case(value: str) -> bool:
    """Whether `value` mixes letter cases, which no correctly written IBAN does.

    This is what makes reading a run longest-first safe. Runs continue across single
    spaces, so `GB29 NWBK 6016 1331 9268 19 was the account` is one run and the words
    after the IBAN are candidate characters. An IBAN is uppercase alphanumerics by
    specification, so a candidate holding both cases has swallowed prose and is refused.

    Written as case *consistency* rather than as uppercase, so someone who typed their
    IBAN in lower case is still covered. The residual gap is a run where the following
    words are also capitals, and it costs a wider span rather than a missed IBAN.
    """
    letters = [character for character in value if character.isalpha()]
    return not (
        any(character.islower() for character in letters)
        and any(character.isupper() for character in letters)
    )


def _iban_starts(text: str, run: list[_Group]) -> list[int]:
    """The group indices in `run` where an IBAN could begin, by its first four.

    A prefilter, and it pays for itself: on the 396 character reference input, which has
    no IBAN in it, candidate enumeration alone built 93 slices and cost 0.17 of the
    pass's 0.21 ms, all of it to discover that no English word is followed by two
    digits. Measured 2026-08-12: 0.21 ms before this, 0.06 ms after.

    The four characters are gathered across groups rather than taken from one, so `GB 29
    NWBK` is found as well as `GB29 NWBK`.
    """
    out: list[int] = []
    for index in range(len(run)):
        head = ""
        for start, end in run[index:]:
            head += text[start:end]
            if len(head) >= 4:
                break
        if len(head) >= 4 and _IBAN_HEAD.match(head[:4]):
            out.append(index)
    return out


def _digit_runs(text: str, run: list[_Group]) -> list[list[_Group]]:
    """The maximal stretches of `run` whose every group is digits.

    A PAN is digits throughout, so a group with a letter in it splits the run rather
    than being skipped over: the groups either side of it are not adjacent.
    """
    out: list[list[_Group]] = []
    current: list[_Group] = []
    for group in run:
        if text[group[0] : group[1]].isdigit():
            current.append(group)
            continue
        if current:
            out.append(current)
        current = []
    if current:
        out.append(current)
    return out


def find(text: str) -> list[tuple[tuple[int, int], str]]:
    """Every card number and IBAN in `text` that its own checksum confirms.

    Spans index the caller's string and never overlap each other. IBANs are resolved
    first: an IBAN holds long digit runs, and having the stronger claim take its
    characters first is what stops part of one being reported as a card.
    """
    accepted: list[tuple[tuple[int, int], str]] = []

    def free(span: tuple[int, int]) -> bool:
        return not any(
            span[0] < taken[1] and taken[0] < span[1] for taken, _ in accepted
        )

    runs = _runs(text)
    for run in runs:
        starts = _iban_starts(text, run)
        if not starts:
            continue
        for start, end in _candidates(run, _IBAN_MIN, _IBAN_MAX, starts):
            value = text[start:end]
            compact = "".join(character for character in value if _is_body(character))
            if not _IBAN_HEAD.match(compact) or not _one_case(value):
                continue
            if free((start, end)) and iban_ok(compact):
                accepted.append(((start, end), IBAN))

    for run in runs:
        for digits_only in _digit_runs(text, run):
            for start, end in _candidates(digits_only, _CARD_MIN, _CARD_MAX):
                digits = "".join(
                    character for character in text[start:end] if character.isdigit()
                )
                if free((start, end)) and _is_pan(digits) and luhn_ok(digits):
                    accepted.append(((start, end), CARD))

    return sorted(accepted)


def supplement(
    text: str,
    spans: dict[tuple[int, int], tuple[str, float]],
) -> dict[tuple[int, int], tuple[str, float]]:
    """Add every checksum-verified entity, and drop the model spans they contain.

    A model span inside a verified one is a fragment of it, mislabelled: the four digits
    the model called a national ID are part of the card number this pass found. Keeping
    both would put a finding in the record that is not true, and dropping it costs no
    coverage because the verified span covers every character it did.

    A span that only partly overlaps is kept as well as the verified one. Redaction
    resolves overlapping spans to their outermost extent, so keeping both widens a
    placeholder at worst, while dropping one could leave characters it covered outside
    every span that remains.

    One consequence to know about: a policy that has disabled `card` filters the
    verified finding out afterwards, so the mislabelled fragment goes and nothing takes
    its place. That is a caller who asked not to be told about card numbers being not
    told about one.
    """
    verified = find(text)
    if not verified:
        return spans
    out = {
        span: value
        for span, value in spans.items()
        if not any(taken[0] <= span[0] and span[1] <= taken[1] for taken, _ in verified)
    }
    for span, label in verified:
        out[span] = (label, VERIFIED_SCORE)
    return out
