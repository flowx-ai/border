# SPDX-License-Identifier: Apache-2.0
"""Tests for the folding and matching core shared by the ported detectors.

Two kinds of test here, and the second kind is the point of the file.

**Offsets survive folding.** Folding changes length in three different directions: ß
becomes two characters, a zero-width character becomes none, a whitespace run becomes
one space. Every one of those is a chance to hand the caller a span that does not index
their string, and the engine redacts spans without checking them, so a wrong span
silently corrupts output. These are the tests that would catch it.

**The upstream bugs, reproduced as assertions.** Each one is a real behaviour of the
Guardrails Hub validator this code replaces, written here as the thing that must not
happen again. `test_lower_would_have_*` names are deliberate: they assert both that the
old approach fails and that this one does not, so the test still means something to
somebody who never read the original.
"""

from __future__ import annotations

import unicodedata

import pytest

from flowx_border.detectors.multilingual import (
    compile_terms,
    find_terms,
    fold,
    fold_text,
    shingles,
)

# ------------------------------------------------------------------ offsets survive


def test_a_span_over_folded_text_indexes_the_original() -> None:
    # The whole reason fold returns offsets rather than just a string.
    original = "Straße"
    folded = fold(original)
    assert folded.text == "strasse"
    assert folded.span(0, len(folded.text)) == (0, len(original))
    assert original[slice(*folded.span(0, len(folded.text)))] == original


def test_a_span_covers_a_zero_width_character_that_folded_away() -> None:
    # If the span stopped short, a redaction would leave the invisible character behind
    # and the next reader of that text would see the term reassemble.
    original = "ac​me"
    folded = fold(original)
    assert folded.text == "acme"
    start, end = folded.span(0, 4)
    assert original[start:end] == original


def test_a_span_covers_a_whole_collapsed_whitespace_run() -> None:
    original = "acme  \n corp"
    folded = fold(original)
    assert folded.text == "acme corp"
    assert original[slice(*folded.span(0, len(folded.text)))] == original


def test_every_folded_character_maps_inside_the_original() -> None:
    for original in ("Straße", "ac​me", "a  b", "İSTANBUL", "ΟΔΌΣ", "naïve"):
        folded = fold(original)
        assert len(folded.starts) == len(folded.text) == len(folded.ends), original
        for start, end in zip(folded.starts, folded.ends, strict=True):
            assert 0 <= start < end <= len(original), original


def test_an_empty_span_raises_rather_than_returning_a_zero_width_one() -> None:
    # A zero-width span in a Finding would redact nothing while claiming otherwise.
    folded = fold("acme")
    with pytest.raises(ValueError, match="empty folded span"):
        folded.span(2, 2)


def test_folding_an_empty_string_is_empty_rather_than_an_error() -> None:
    assert fold("").text == ""


# --------------------------------------------------------- the upstream casing bugs


def test_lower_would_have_missed_german_ss_and_casefold_does_not() -> None:
    # `ban_list` lowercases. In German that leaves two spellings of one word unequal,
    # so a term list containing either one misses the other.
    assert "STRASSE".lower() != "Straße".lower()
    assert fold_text("STRASSE") == fold_text("Straße") == "strasse"


def test_lower_would_have_missed_greek_medial_sigma_and_casefold_does_not() -> None:
    """The Greek case is narrower than it looks, so it is worth stating exactly.

    Python's `str.lower()` does implement the final-sigma rule, so lowercasing ΛΑΘΟΣ
    correctly gives a word ending in ς. What it does not do is unify ς with σ. Any
    source that lowercased without that rule, and any writer using a keyboard that does
    not distinguish them, produces the medial spelling, and under `lower` the two are
    different strings. casefold maps both onto σ.
    """
    assert "ΛΑΘΟΣ".lower().endswith("ς")  # lower gets the final sigma right
    assert "ΛΑΘΟΣ".lower() != "λαθοσ"  # and still does not match the medial spelling
    assert fold_text("ΛΑΘΟΣ") == fold_text("λαθοσ") == fold_text("λαθος")


def test_turkish_dotted_capital_i_matches_its_lowercase_form() -> None:
    # casefold alone turns İ into i plus a combining dot above, so casefolding is not
    # by itself enough here.
    assert len("İ".casefold()) == 2
    assert fold_text("İSTANBUL") == fold_text("istanbul") == "istanbul"


def test_romanian_comma_below_and_cedilla_are_one_letter() -> None:
    # Two encodings of the same letter, both in daily use. NFC does not unify them,
    # so without this a Romanian term list matches roughly half of Romanian text.
    comma, cedilla = "ș", "ş"
    assert comma != cedilla
    assert unicodedata.normalize("NFC", comma) != unicodedata.normalize("NFC", cedilla)
    assert fold_text("informație") == fold_text("informaţie")
    assert fold_text("București") == fold_text("Bucureşti")


def test_a_typographic_apostrophe_matches_an_ascii_one() -> None:
    # French, Italian and Irish terms are written with ' in a policy file and arrive
    # with the smart-quote form from any editor that has smart quotes on.
    assert fold_text("j'ai reçu") == fold_text("j’ai reçu")


def test_decomposed_and_precomposed_input_fold_alike() -> None:
    text = "Acest răspuns"
    assert fold_text(text) == fold_text(unicodedata.normalize("NFD", text))


def test_diacritics_are_kept_unless_asked_for() -> None:
    # Off by default because dropping them merges real words: Swedish far and fär.
    assert fold_text("sărbătoare") != fold_text("sarbatoare")
    assert fold_text("sărbătoare", diacritics=True) == fold_text(
        "sarbatoare", diacritics=True
    )
    assert fold_text("far", diacritics=True) == fold_text("fär", diacritics=True)


# --------------------------------------------------------------- markup-only folding


def test_compatibility_folding_is_off_for_prose_and_on_for_markup() -> None:
    fullwidth = "ｊａｖａｓｃｒｉｐｔ"
    assert fold_text(fullwidth) != "javascript"
    assert fold_text(fullwidth, compat=True) == "javascript"


def test_entities_are_decoded_only_when_asked_for() -> None:
    assert fold_text("&#106;avascript") == "&#106;avascript"
    assert fold_text("&#106;avascript", entities=True) == "javascript"
    assert fold_text("&lt;script&gt;", entities=True) == "<script>"


def test_an_unknown_entity_stays_literal() -> None:
    assert fold_text("&notareference;", entities=True) == "&notareference;"


def test_a_decoded_entity_span_covers_the_whole_reference() -> None:
    original = "&#106;s"
    folded = fold(original, entities=True)
    assert folded.text == "js"
    assert folded.span(0, 1) == (0, 6)


# ------------------------------------------------------------------ term matching


def test_a_term_does_not_match_across_a_word_boundary() -> None:
    """The `ban_list` false positive it cannot avoid, because it deletes the spaces.

    Upstream strips every space from the text before searching, so `car sedan` becomes
    `carsedan` and a banned word appears inside it that no reader of the text can see.
    Preserving the boundary is what makes that impossible here, so this holds even with
    word matching switched off.
    """
    haystack = fold("I drive a car sedan every day.")
    assert "arse" in "I drive a car sedan every day.".replace(" ", "")
    assert find_terms(haystack, ("arse",)) == []
    assert find_terms(haystack, ("arse",), whole_words=False) == []
    assert find_terms(haystack, ("car",)) != []


def test_word_boundaries_stop_a_term_matching_inside_a_longer_word() -> None:
    # The other half of the same problem, and the reason whole_words defaults to true.
    haystack = fold("The data is sparse this quarter.")
    assert find_terms(haystack, ("arse",)) == []
    assert find_terms(haystack, ("arse",), whole_words=False) != []


def test_a_term_matches_regardless_of_case_and_encoding() -> None:
    haystack = fold("Ne vedem la BUCUREŞTI mâine.")
    assert len(find_terms(haystack, ("bucurești",))) == 1


def test_a_term_split_by_a_zero_width_character_still_matches() -> None:
    # The evasion no upstream validator here handles.
    haystack = fold("Contact ac​me today.")
    found = find_terms(haystack, ("acme",))
    assert len(found) == 1
    start, end = found[0][0], found[0][1]
    assert "Contact ac​me today."[start:end] == "ac​me"


def test_a_multi_word_term_matches_across_collapsed_whitespace() -> None:
    haystack = fold("Contact Acme\n  Corporation today.")
    assert len(find_terms(haystack, ("acme corporation",))) == 1


def test_the_longest_term_wins_when_two_overlap() -> None:
    haystack = fold("Acme Corporation is here.")
    found = find_terms(haystack, ("acme", "acme corporation"))
    assert len(found) == 1
    assert found[0][2] == "acme corporation"


def test_an_empty_term_list_compiles_to_nothing_rather_than_to_everything() -> None:
    # A pattern built from no alternatives matches the empty string at every position,
    # which would be a detector that reports a finding per character.
    assert compile_terms((), True) is None
    assert find_terms(fold("anything at all"), ()) == []


def test_blank_terms_are_dropped_rather_than_matching_everywhere() -> None:
    assert compile_terms(("", "   "), True) is None


def test_a_term_containing_regex_metacharacters_is_matched_literally() -> None:
    haystack = fold("The rate is c++ or 3.5 percent.")
    assert len(find_terms(haystack, ("c++",))) == 1
    assert find_terms(haystack, ("3x5",)) == []


# ------------------------------------------------------------------------ shingles


def test_shingles_are_overlapping_word_ngrams() -> None:
    assert shingles("a b c d", 2) == ["a b", "b c", "c d"]


def test_a_text_shorter_than_the_window_is_one_shingle() -> None:
    assert shingles("a b", 5) == ["a b"]


def test_an_empty_text_has_no_shingles() -> None:
    assert shingles("", 5) == []
    assert shingles("   ", 5) == []
