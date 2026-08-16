# SPDX-License-Identifier: Apache-2.0
"""Tests for the national identifier repair pass.

The measurement behind it: on the held-out frames the tagger scored NATIONAL_ID at F1
0.1429 with `missed_spans: 0`. It finds every identifier and tears the long ones, which
exact-span scoring counts as two false positives and a miss. `ro` is the worked example,
`1366485628020` coming back as `136648` and `20`.

The safety argument these tests exist to hold is narrow and load bearing: this may only
ever repair a span the model already claimed. The check digits are one-in-ten by chance,
so a pass that went looking for identifiers would label an order number as one in ten
percent of documents. Nothing here may widen into discovery.
"""

from __future__ import annotations

from flowx_border.detectors._national_id_checks import (
    valid_cnp,
    valid_egn,
    valid_nir,
    valid_pesel,
)
from flowx_border.detectors.national_id_shapes import repair, validates


def spans(text: str, found: dict[tuple[int, int], tuple[str, float]]) -> set[str]:
    return {f"{entity}:{text[s:e]}" for (s, e), (entity, _) in found.items()}


def test_a_torn_identifier_is_rejoined() -> None:
    """The exact fragmentation observed on ro, with the real CNP that produced it."""
    identifier = "1366485628020"
    text = f"The file is registered under {identifier} at present."
    base = text.index(identifier)
    torn = {
        (base, base + 6): ("national_id", 0.9),
        (base + 11, base + 13): ("national_id", 0.8),
    }
    assert spans(text, repair(text, torn)) == {f"national_id:{identifier}"}


def test_a_card_that_fails_luhn_and_is_a_national_id_is_relabelled() -> None:
    """The other half of the observed failure: fr came back labelled CARD.

    Failing Luhn is what makes this safe. A real card passes it, so this branch cannot
    reach one, and `checksummed.py` runs its own Luhn afterwards and wins regardless.
    """
    nir = "718792685065940"
    assert valid_nir(nir)
    text = f"Reference {nir} on file."
    base = text.index(nir)
    repaired = repair(text, {(base, base + 15): ("card", 0.9)})
    assert spans(text, repaired) == {f"national_id:{nir}"}


def test_a_real_card_is_left_alone() -> None:
    """The direction that would be a genuine regression: a card called an identifier.

    `4548838822105536` is Luhn valid, so the relabel branch never sees it. If this ever
    fails, an evidence record is about to say "national identifier" where a payment card
    was, and `checksummed.py` would then have to argue with a span this pass moved.
    """
    pan = "4548838822105536"
    text = f"Card {pan} charged."
    base = text.index(pan)
    assert spans(text, repair(text, {(base, base + 16): ("card", 0.9)})) == {
        f"card:{pan}"
    }


def test_it_never_invents_a_span() -> None:
    """The safety property. No input of unclaimed text may produce a finding.

    Every check digit here admits about one run in ten by chance, so discovery is the
    thing this module must not do. A text full of valid identifiers that the model said
    nothing about must come back untouched.
    """
    text = "Order 1366485628020 shipped, invoice 8645428419, ref 05075906310."
    assert valid_cnp("1366485628020")
    assert valid_egn("8645428419")
    assert valid_pesel("05075906310")
    assert repair(text, {}) == {}

    # And a claim about something else is not converted into a national identifier.
    person = {(0, 5): ("person", 0.9)}
    assert repair(text, person) == person


def test_fragments_separated_by_words_are_not_joined() -> None:
    """Two identifiers in a list are two identifiers, not one torn in half.

    The gap between fragments has to be digits. Joining across a word would merge two
    people's identifiers into a single span, which over-redacts and, worse, puts one
    finding in the record where two belong.
    """
    text = "Holders 1366485628020 and 8645428419 are listed."
    first = text.index("1366485628020")
    second = text.index("8645428419")
    claimed = {
        (first, first + 13): ("national_id", 0.9),
        (second, second + 10): ("national_id", 0.9),
    }
    assert repair(text, claimed) == claimed


def test_a_join_that_does_not_validate_is_left_torn() -> None:
    """Rejoining is only done when the joined run passes a scheme.

    Otherwise the pass would widen spans on the strength of two fragments being near
    each other, which is a guess. Leaving it torn is the honest outcome: the model's
    spans are reported as the model produced them.
    """
    text = "Values 1234567890123 recorded."
    assert validates("1234567890123") is None
    base = text.index("1234567890123")
    torn = {
        (base, base + 6): ("national_id", 0.9),
        (base + 11, base + 13): ("national_id", 0.8),
    }
    assert repair(text, torn) == torn


def test_the_ported_validators_accept_what_the_generator_makes() -> None:
    """These were copied out of the training repo, so they have to still agree with it.

    Verified against 300 generated values per scheme when the port was made; this pins
    one known-good value each so a future edit to the weights fails here rather than in
    a corpus six weeks later.
    """
    assert valid_cnp("1366485628020")
    assert valid_egn("8645428419")
    assert valid_pesel("05075906310")
    assert valid_nir("718792685065940")
    assert not valid_cnp("1366485628021")
    assert not valid_egn("8645428410")
