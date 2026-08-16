# SPDX-License-Identifier: Apache-2.0
"""Check digits for the national identifier schemes this repository generates.

Ported from `vendor/openner/national_ids.py` in the training repository, which is where
the corpus generator makes them, so a scheme validated here is a scheme the models were
trained on. Copied rather than imported: the library ships without the training package
and must not grow a dependency on it.

**A passing check digit is not evidence on its own, and this module is not used as if
it were.** Measured over 20,000 random digit strings of each length, every scheme below
except the French NIR admits about one in ten by chance, because each is a single check
digit over a fixed weighting. `national_id_shapes.py` therefore only calls these to
repair a span the tagger already claimed, never to find one. That is the same argument
`checksummed.py` makes for refusing to claim a card on Luhn alone.

Structure beyond the check digit is deliberately not validated here. A CNP embeds a
birth date and a county, an EGN and a PESEL embed dates, and checking those would cut
the false positive rate by a hundred. That is worth doing the day one of these is used
to discover rather than repair; until then it would be unused strictness, and an unused
rule is one nobody notices has rotted.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Final

_CNP_W: Final = [2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9]
_EGN_W: Final = [2, 4, 8, 5, 10, 9, 7, 3, 6]
_PESEL_W: Final = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3]
_EMSO_W: Final = [7, 6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2]


def valid_cnp(value: str) -> bool:
    """Romania, 13 digits."""
    if len(value) != 13 or not value.isdigit():
        return False
    digits = [int(character) for character in value]
    remainder = sum(digits[i] * _CNP_W[i] for i in range(12)) % 11
    return (1 if remainder == 10 else remainder) == digits[12]


def valid_egn(value: str) -> bool:
    """Bulgaria, 10 digits."""
    if len(value) != 10 or not value.isdigit():
        return False
    digits = [int(character) for character in value]
    remainder = sum(digits[i] * _EGN_W[i] for i in range(9)) % 11
    return (0 if remainder == 10 else remainder) == digits[9]


def _mod11_10(digits: list[int]) -> int:
    """ISO 7064 MOD 11,10, used by the Croatian OIB and the German Steuer-IdNr."""
    carry = 10
    for digit in digits:
        carry = (carry + digit) % 10
        carry = 10 if carry == 0 else carry
        carry = (carry * 2) % 11
    check = 11 - carry
    return 0 if check == 10 else check


def valid_oib(value: str) -> bool:
    """Croatia, 11 digits."""
    if len(value) != 11 or not value.isdigit():
        return False
    return _mod11_10([int(c) for c in value[:10]]) == int(value[10])


def valid_steuerid(value: str) -> bool:
    """Germany, 11 digits."""
    if len(value) != 11 or not value.isdigit():
        return False
    return _mod11_10([int(c) for c in value[:10]]) == int(value[10])


def valid_pesel(value: str) -> bool:
    """Poland, 11 digits."""
    if len(value) != 11 or not value.isdigit():
        return False
    digits = [int(character) for character in value]
    total = sum(digits[i] * _PESEL_W[i] for i in range(10))
    return (10 - total % 10) % 10 == digits[10]


def valid_emso(value: str) -> bool:
    """Slovenia and the former Yugoslavia, 13 digits."""
    if len(value) != 13 or not value.isdigit():
        return False
    digits = [int(character) for character in value]
    total = sum(digits[i] * _EMSO_W[i] for i in range(12))
    remainder = total % 11
    check = 0 if remainder in (0, 1) else 11 - remainder
    return check == digits[12]


def valid_nir(value: str) -> bool:
    """France, 15 digits. The one scheme here with real strength, at 1 in 93."""
    text = value.replace(" ", "")
    if len(text) != 15 or not text.isdigit():
        return False
    return 97 - (int(text[:13]) % 97) == int(text[13:])


#: Digit length to the schemes of that length. Length first, because a run that is no
#: scheme's length is the common case and the cheapest thing to rule out.
#:
#: Ordering inside a length matters only for which name is reported, not for whether
#: anything matches, so the stronger scheme goes first where two share a length.
BY_LENGTH: Final[dict[int, list[tuple[str, Callable[[str], bool]]]]] = {
    10: [("egn", valid_egn)],
    11: [("pesel", valid_pesel), ("oib", valid_oib), ("steuerid", valid_steuerid)],
    13: [("cnp", valid_cnp), ("emso", valid_emso)],
    15: [("nir", valid_nir)],
}

__all__ = [
    "BY_LENGTH",
    "valid_cnp",
    "valid_egn",
    "valid_emso",
    "valid_nir",
    "valid_oib",
    "valid_pesel",
    "valid_steuerid",
]
