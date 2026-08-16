# SPDX-License-Identifier: Apache-2.0
"""National identifiers the tagger found and then cut in half.

Added 2026-08-16, after held-out evaluation put `NATIONAL_ID` at F1 0.0970 on the
published model and 0.1429 on the frame-trained one, and the cause turned out not to be
the one recorded for four days. It is not that the tagger calls national IDs cards.
Measured across twelve locales on one frame, eleven get the label right:

    ro  1366485628020   ->  '136648' and '20'      two spans, the middle dropped
    fr  718792685065940 ->  one span, labelled CARD
    bg  8645428419      ->  correct
    de  32883581148     ->  correct

So the failure is a **fragmented span**, the same shape as the `DATE` failure and not
the `CARD` confusion. A long digit run tokenises into five or six subwords and the
tagger tags some of them, which exact-span scoring counts as two false positives and a
miss.

Why this repairs rather than discovers
---------------------------------------

`checksummed.py` finds cards and IBANs in text the model never touched, and it can,
because a Luhn-valid 16-digit PAN with an issuer prefix is rare by accident. National
identifiers are not like that. Measured over 20,000 random digit strings of the right
length for each scheme:

    valid_cnp        1 in 10        valid_emso       1 in 10
    valid_egn        1 in 9         valid_tax_hu     1 in 11
    valid_oib        1 in 10        valid_nir        1 in 93
    valid_steuerid   1 in 10

These are single check-digit schemes. A pass that went looking would call one order
number in ten a national identifier and write that into a signed evidence record, which
is what `checksummed.py` refuses to do for cards on the same arithmetic.

So this only ever repairs a span the model already claimed. The model has said "there is
a national identifier here" and been right about that in eleven of twelve locales; what
it got wrong is where the identifier ends. Joining two of its own fragments, when the
joined run validates, adds no new claim. That keeps the false-positive rate at the
model's rather than at the checksum's.

What it does, in order
-----------------------

**Rejoins fragments.** Two or more `national_id` spans separated only by digits of the
same run become one span when the whole run validates under some scheme. The gap has to
be digits: an identifier does not span a word.

**Relabels a card that is not one.** A span the model called `card` whose digits fail
Luhn, and which validates as a national identifier, is relabelled. Failing Luhn is the
load-bearing half: a real card passes it, so this cannot take a card away from
`checksummed.py`, which runs its own Luhn check and wins on anything that passes.

Both are span-preserving or span-widening. Nothing here narrows a span or drops one, so
no path through this module can turn a redaction into a disclosure.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Final

#: Length to the schemes that issue it. Keyed by length first because that is the cheap
#: test, and a run that is no scheme's length is the common case.
#:
#: Deliberately not exhaustive over the 26 languages. A scheme belongs here when this
#: repository has a validator for it, and the rest stay the model's problem rather than
#: being guessed at with a rule nobody checked.
_DIGITS: Final = re.compile(r"\d")


def _luhn(digits: str) -> bool:
    total = 0
    for index, character in enumerate(reversed(digits)):
        value = int(character)
        if index % 2:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _validators() -> dict[int, list[tuple[str, Callable[[str], bool]]]]:
    """Scheme validators from the vendored generator, grouped by digit length.

    Imported lazily and defensively. The library ships without the training package, so
    a missing module means this repair does not run rather than that a scan fails: the
    tagger's own spans are still reported and nothing is lost that was there before.
    """
    try:
        from flowx_border.detectors import _national_id_checks as checks
    except ImportError:  # pragma: no cover - exercised by the absent-module test
        return {}
    return checks.BY_LENGTH


def validates(run: str) -> str | None:
    """The first scheme this digit run satisfies, or None.

    Returns the scheme name rather than a boolean so a finding can say which one, and so
    a reader of the code can see that "validates" never means "is a national identifier"
    on its own. It means "could be, and the model already said it was".
    """
    table = _validators()
    for name, check in table.get(len(run), []):
        try:
            if check(run):
                return name
        except (ValueError, TypeError):  # pragma: no cover - odd input to a scheme
            continue
    return None


def repair(
    text: str,
    spans: dict[tuple[int, int], tuple[str, float]],
) -> dict[tuple[int, int], tuple[str, float]]:
    """Rejoin torn national identifiers, and relabel a card that fails Luhn."""
    if not spans:
        return spans

    out = dict(spans)

    # 1. Rejoin fragments. Sorted so neighbours are adjacent in the walk.
    national = sorted(
        span for span, (entity, _) in spans.items() if entity == "national_id"
    )
    index = 0
    while index < len(national):
        start, end = national[index]
        merged_score = spans[national[index]][1]
        joined = [national[index]]
        step = index + 1
        while step < len(national):
            next_start, next_end = national[step]
            between = text[end:next_start]
            # Digits only between them, and not a huge gap: this is one run the tagger
            # tore, not two identifiers in a list.
            if between and (not between.isdigit() or len(between) > 8):
                break
            candidate = text[start:next_end]
            if not candidate.replace(" ", "").isdigit():
                break
            end = next_end
            joined.append(national[step])
            merged_score = max(merged_score, spans[national[step]][1])
            step += 1

        if len(joined) > 1 and validates(text[start:end]):
            for piece in joined:
                out.pop(piece, None)
            out[(start, end)] = ("national_id", merged_score)
            index = step
            continue
        index += 1

    # 2. A card that fails Luhn and validates as an identifier was never a card.
    for span, (entity, score) in list(spans.items()):
        if entity != "card":
            continue
        digits = "".join(_DIGITS.findall(text[span[0] : span[1]]))
        if not digits or _luhn(digits):
            # Passing Luhn keeps it a card, and checksummed.py has the final say there.
            continue
        if validates(digits):
            out[span] = ("national_id", score)

    return out


__all__ = ["repair", "validates"]
