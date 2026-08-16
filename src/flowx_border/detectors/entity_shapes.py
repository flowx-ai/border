# SPDX-License-Identifier: Apache-2.0
"""Whether a span the model tagged can be the entity type it was tagged as.

Added 2026-08-12 after a held-out evaluation of piiguard found it tagging number words
in ordinary prose: `nine` as an EMAIL and `five.` as a DATE in English, `nio` as a
PERSON and `fem.` as a DATE in Swedish. An email address with no `@` in it is not an
email address, and that is checkable without a model.

**The direction of failure is the whole design.** This runs inside a redactor. A gate
that drops a real entity turns a false positive into a hole in a redaction, which the
caller cannot see and which is strictly worse than the noise it was added to remove. So
the rule is narrow on purpose:

- **Impossible, so dropped.** An EMAIL with no `@`, a DATE with no digit, a CARD with
  four digits, an IBAN of ten characters. Nothing that is genuinely one of these can
  fail these checks, so dropping costs no recall. This is where three of the four
  measured false positives die.
- **Merely wrong, so kept and recorded.** An IBAN that fails mod-97, a card number that
  fails Luhn. A checksum failure is as likely to mean a typo, a test number, or a span
  the model got the boundary of, and all three of those are still personal data. Redact
  them and say the checksum did not pass.

The second half is the one worth defending, because a checksum is the strongest signal
here and not using it to drop looks like waste. It is not: `4111 1111 1111 1112` fails
Luhn and is obviously still a card number to redact, and a span that clipped an IBAN's
last character fails mod-97 while still carrying most of an account number.

The two halves are about different questions and the IBAN appears in both, which is
worth being precise about. Length is the first: under 15 characters it cannot be an
IBAN under ISO 13616, so it is dropped. Mod-97 is the second: at a legal length and a
failing checksum it is very likely an account number with something wrong with it, so it
is kept and the record says the checksum did not pass.

**PERSON has no shape and gets no check.** A name is any string. One of the four
measured false positives was a PERSON and it survives this module, which is stated here
rather than papered over: closing that one needs the corpus to contain sentences with no
entities in them, which is a training-side fix.

Nothing here is language-specific. Digits, `@` and letter counts mean the same thing in
all 26, which is why this module has no per-language table and why its tests sweep
scripts rather than languages.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Final

#: Reported when a span was dropped, one per rejected span, always at `log`. A drop is a
#: decision the record has to show. Silently removing a finding would leave an evidence
#: record that is indistinguishable from one where the model found nothing, which is the
#: no-op this library treats as a vulnerability.
REJECTED_PREFIX: Final = "pii_shape_rejected_"

#: Reported when a span's type was corrected, one per span, at `log`, naming the type
#: the model gave it. The record has to show the correction for the same reason it shows
#: a drop: an evidence record that quietly disagrees with the model it attests is worse
#: than one that says what happened.
RELABELLED_PREFIX: Final = "pii_relabelled_from_"

#: Reported when a span was kept despite failing its checksum, one per span, at `log`.
UNVERIFIED_PREFIX: Final = "pii_checksum_failed_"

_DIGITS: Final = re.compile(r"\d")

#: ISO 13616: an IBAN is 15 to 34 characters. The floor is duplicated in
#: `checksummed.py`, which needs it to scan raw text, and the two are pinned equal by a
#: test rather than by a shared constant, so that neither module reaches into the other
#: for a number the standard gives both of them.
_IBAN_MIN: Final = 15
#: An address needs a local part, an `@`, and a dot in the domain after it. Deliberately
#: not a full RFC 5322 pattern: the question is whether this can be an address at all,
#: and an over-strict pattern here would drop real addresses, which is the failure
#: direction this module exists to avoid.
_EMAIL: Final = re.compile(r"[^@\s]@[^@\s]*\.[^@\s]")

#: The same shape anchored, for deciding that a span *is* an address rather than that it
#: could contain one. `corrected_label` needs the stricter reading: renaming a whole
#: sentence because an address sits inside it would move a label onto text that is not
#: the address.
_EMAIL_WHOLE: Final = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")

#: Sentence punctuation that can sit against an entity without being part of it. A set
#: of single characters, spelled out so that it reads as a set rather than as the string
#: it would look like inside a strip() call.
_TRAILING: Final = "".join(
    (
        ".",
        ",",
        ";",
        ":",
        "!",
        "?",
        '"',
        "'",
        "(",
        ")",
        "[",
        "]",
        "\u00ab",
        "\u00bb",
        "\u201c",
        "\u201d",
    )
)


def _digit_count(value: str) -> int:
    return sum(1 for character in value if character.isdigit())


def _alnum_count(value: str) -> int:
    """ASCII alphanumerics only, which is what ISO 13616 defines an IBAN over.

    Normalised first so that a full-width digit or a non-breaking space cannot make a
    span look shorter than it is. The false positives this floor exists to kill are full
    of narrow no-break spaces, which are not alphanumeric either way.
    """
    return sum(
        1
        for character in unicodedata.normalize("NFKC", value)
        if character.isascii() and character.isalnum()
    )


def luhn_ok(digits: str) -> bool:
    """The Luhn check for a card number, over the digits only."""
    body = [int(character) for character in digits if character.isdigit()]
    if len(body) < 2:
        return False
    total = 0
    for index, digit in enumerate(reversed(body)):
        if index % 2:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def iban_ok(value: str) -> bool:
    """ISO 13616 mod-97, which is 1 for a well formed IBAN.

    Case folded and stripped of separators first, because a caller's text carries the
    spaced presentation form and the algorithm is defined over the compact one.
    """
    compact = "".join(character for character in value.upper() if character.isalnum())
    if len(compact) < 15 or not compact[:2].isalpha() or not compact[2:4].isdigit():
        return False
    rearranged = compact[4:] + compact[:4]
    total = 0
    for character in rearranged:
        if character.isdigit():
            total = (total * 10 + int(character)) % 97
        elif character.isalpha():
            total = (total * 100 + (ord(character) - 55)) % 97
        else:
            return False
    return total == 1


def corrected_label(entity: str, value: str) -> str | None:
    """The type this span obviously is, when the model called it something else.

    Added 2026-08-16, when the adopted piiguard artifact was found labelling
    `ivan.horvat@primjer.hr` as `person` in Croatian and Slovenian. The span was whole
    and the text was still redacted, so nothing leaked; what broke was the record, which
    said a person where an address was, and `output_leakage`, which looks for a leaked
    email by name.

    It is the neighbour axis the held-out harness already measures: the mislabel appears
    only where a person's name precedes the address, and Hungarian, English and German
    are unaffected because their probe sentences put nothing in front of it.

    **Only ever a relabel, never a drop and never a new span.** An address is not a
    name, so this direction is safe in a way the reverse is not: turning `person` into
    `email` on a string containing `@` cannot hide anything, while a rule that turned
    `email` into something else could. The span is untouched, so a redactor removes
    exactly the same characters either way and only the name in the record changes.

    Returns None when there is nothing to correct, which is the overwhelmingly common
    case.
    """
    if entity.upper() == "EMAIL":
        return None
    core = value.strip().strip(_TRAILING)
    # The whole span has to be the address. A sentence that merely contains one is a
    # span whose boundaries the model got wrong, and widening or renaming that would be
    # guessing at which part it meant.
    if core and _EMAIL_WHOLE.fullmatch(core):
        return "email"
    return None


def is_possible(entity: str, value: str) -> bool:
    """Can this text be this entity type at all?

    False only where the answer is no by construction. Anything uncertain returns True
    and is left to the checksum layer or to the caller, because this decides whether to
    redact.
    """
    # Upper cased because the model's labels are lower case and this module's names are
    # not. Without this every comparison below missed and the function returned True for
    # everything, which is a gate that silently does nothing: found on 2026-08-12 when a
    # DATE span reading `March` survived a check that requires a digit. The unit tests
    # did not catch it because they called this function directly with the upper case
    # name, which is why there is now one that goes through the detector.
    entity = entity.upper()
    stripped = value.strip()
    if not stripped:
        return False
    # Trailing sentence punctuation is not part of any of these entities and is what the
    # model attached to `five.` and `fem.`. Stripped before measuring rather than
    # treated as a rejection, so that `14 March 2024.` is still a date.
    core = stripped.strip(_TRAILING)
    if not core:
        return False

    if entity == "EMAIL":
        return _EMAIL.search(core) is not None
    if entity == "DATE":
        # Every calendar system in the supported set writes a date with at least one
        # digit. A month name alone is not a date, and `five.` is not a date.
        return _DIGITS.search(core) is not None
    if entity == "PHONE":
        # Five is the floor rather than a realistic minimum: short codes exist, and the
        # point is to exclude number words and single figures rather than to validate
        # dialling plans, which differ per country and are the caller's business.
        return _digit_count(core) >= 5
    if entity == "CARD":
        # No card scheme in use has fewer than twelve digits.
        return _digit_count(core) >= 12
    if entity == "IBAN":
        # ISO 13616 puts an IBAN between 15 and 34 characters, so anything shorter
        # cannot be one. `checksummed.py` reads the same floor from the same standard.
        #
        # This deliberately reverses what stood here until 2026-08-16, which was two
        # letters and four digits, on the stated grounds that "a span that clipped an
        # IBAN should be redacted rather than dropped". Two things make the reversal
        # safe, and the second is the one that matters:
        #
        # - Four digits is not a weak floor, it is no floor. It let `5000 mAh`, `6,5",
        #   128 GB` and `mm x 80 mm x 45 mm` through as IBANs on ordinary product
        #   descriptions, measured over 234 rows in 26 languages.
        # - A real IBAN the model clipped is still redacted, because `checksummed.py`
        #   scans the raw text for mod-97-valid runs without asking the model at all.
        #   The clipped span dies here and the whole IBAN is found there. Verified end
        #   to end in tests/test_entity_shapes.py rather than assumed.
        #
        # So the clipping argument was right about the risk and wrong about who bears
        # it: the checksum pass is the guarantee, and this gate is free to be strict.
        # Same division of labour as CARD, where the model is the recall net and Luhn
        # is the guarantee.
        return _alnum_count(core) >= _IBAN_MIN
    if entity == "NATIONAL_ID":
        # Every scheme in the 26 carries at least four digits, including the two that
        # carry no checksum. Malta's and Azerbaijan's are format-only, which is why this
        # is a digit count rather than a checksum: see the model card.
        return _digit_count(core) >= 4
    if entity == "PERSON":
        # A name is any string, so there is nothing to check and this module says so
        # rather than inventing a heuristic. A capitalisation rule was considered and
        # rejected: it would be wrong in scripts without case, and a lowercase name is a
        # style choice rather than an impossibility.
        return True
    # An entity type this module has not been taught. Kept rather than dropped, because
    # a new label in the model should not silently stop being redacted.
    return True


def checksum_state(entity: str, value: str) -> bool | None:
    """True if a checksum passed, False if it failed, None if there is none to run.

    None is not a failure and the caller must not treat it as one. Most of the seven
    types have no checksum, and `PERSON` never will.
    """
    entity = entity.upper()
    core = "".join(
        character
        for character in unicodedata.normalize("NFKC", value)
        if character.isalnum()
    )
    if entity == "CARD":
        return luhn_ok(core)
    if entity == "IBAN":
        return iban_ok(core)
    return None
