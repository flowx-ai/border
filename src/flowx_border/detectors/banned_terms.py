# SPDX-License-Identifier: Apache-2.0
"""T1: terms the deploying organisation has decided must not appear.

Ported from six Guardrails Hub validators that are the same validator with a different
list baked in: `ban_list`, `contains_string`, `competitor_check`, `mentions_drugs`,
`sky_validator`, and the list half of `profanity_free`. Six packages, one mechanism, and
in every one of them the list is the deployer's data rather than the library's.

So the list is policy, and it ships empty
-----------------------------------------

There is no packaged wordlist here, in any language, and that is a decision rather than
an omission. A competitor list, a drug list and a profanity list are all
customer-specific, they change without a release, and a library that shipped its own
would be asserting an editorial judgement it cannot defend in 26 languages. The library
that ships the mechanism and asks you for the list is being honest about which half it
knows.

**An enabled detector with no terms says so, every scan.** It reports
`terms_not_configured` with action `log` and finds nothing else. Reporting nothing would
be indistinguishable from a clean scan, and the caller would read the absence of
findings as evidence that nothing was found rather than evidence that nothing was
looked for. `log` keeps it out of the verdict, so an unconfigured policy is told rather
than blocked, and the line disappears from the record as soon as the policy either
supplies terms or disables the detector. This is the same shape as
`leakage_unverifiable` in output_leakage.py.

The shipped policies set `enabled: false` for exactly this reason: a detector whose
entire input is customer data should be off until there is customer data.

What the port fixes, and why each one is a 26-language bug
----------------------------------------------------------

`ban_list` lowercases with `str.lower()`, strips every space from the text, then runs a
fuzzy search with an edit distance of one. Four consequences, all of them reachable
from ordinary European text:

1. `.lower()` does not fold German ß onto ss or Greek final sigma onto sigma, so
   `Straße` and `STRASSE` are different words and so are `οδός` and `ΟΔΌΣ`. See
   `multilingual.fold`.
2. Stripping every space turns `car sedan` into `carsedan`, so a term matches across a
   word boundary that a reader can plainly see. Here matching is on word boundaries and
   whitespace is collapsed rather than deleted.
3. Its reported span is off by one: the index map it builds increments the counter
   before recording it, so every span starts one character late. A span that is wrong by
   one character redacts the wrong characters, which is worse than reporting no span.
4. Edit distance one is not portable. In English it absorbs typos; in Romanian, Polish
   and Finnish it merges real, unrelated words that differ by one letter, and it is what
   lets a match cross a word boundary in the first place. This port does not do fuzzy
   matching. A policy that wants a spelling matched lists it in `terms`, which is
   reviewable data rather than a distance threshold whose false positives nobody can
   enumerate.

Two things it adds that no upstream validator has. Zero-width characters are dropped
before matching, so `ac<U+200B>me` does not evade a term, and the span still covers them
so a redaction takes the whole run. Romanian ș spelled with a cedilla matches ș
spelled with a comma below, because those are two encodings of one letter rather
than two letters.

Options
-------

    terms:            list[str], required, the terms to look for
    whole_words:      bool, default true. False matches substrings, which is what
                      `contains_string` did. It is off by default because substring
                      matching is how a banned word flags an innocent one.
    fold_diacritics:  bool, default false. True lets `sarbatoare` match `sărbătoare`,
                      and also lets Swedish `far` match `fär`. Both, or neither.
    label:            str, default `banned_term`. Lets one policy distinguish a
                      competitor list from a profanity list in the evidence record.

Budget is 5 ms at p95 at the reference input, one folding pass plus one alternation.
"""

from __future__ import annotations

import re
from typing import Final

from flowx_border.detectors.base import INPUT, OUTPUT, Context, DetectorConfig
from flowx_border.detectors.multilingual import find_terms, fold, fold_text
from flowx_border.types import Finding

#: Labels reach the evidence record, which constrains them to lowercase identifiers.
#: Checked rather than coerced: silently rewriting a policy's label would put a
#: different string in the audit trail than the one the policy author wrote.
_LABEL: Final = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

DEFAULT_LABEL: Final = "banned_term"


class BannedTermsError(ValueError):
    """The detector is enabled but cannot do the job the policy asked for."""


class BannedTermsDetector:
    """Matches a policy-supplied term list, correctly, in 26 languages."""

    id = "banned_terms"
    tier = "T1"
    sides = frozenset({INPUT, OUTPUT})

    def warm(self) -> None:
        """Nothing to load. The term list arrives per scan, from the policy.

        It cannot be compiled here because two policies may enable this detector with
        different lists, and `compile_terms` caches per list rather than per detector.
        """

    def run(
        self,
        text: str,
        cfg: DetectorConfig,
        ctx: Context,  # noqa: ARG002 - the Detector protocol fixes this signature
    ) -> list[Finding]:
        options = cfg.options
        raw = options.get("terms") or []
        if isinstance(raw, str):
            raw = [raw]

        terms = tuple(str(term) for term in raw if str(term).strip())
        if not terms:
            return [
                Finding(
                    detector_id=self.id,
                    tier=self.tier,
                    label="terms_not_configured",
                    score=1.0,
                    span=None,
                    # Always log. An empty list is a gap in the policy, not a finding
                    # about the text, and blocking traffic over it would punish the
                    # caller for the library's own default.
                    action="log",
                )
            ]

        label = str(options.get("label", DEFAULT_LABEL))
        if not _LABEL.match(label):
            raise BannedTermsError(
                f"banned_terms label {label!r} is not a valid identifier. Labels go "
                "into the evidence record, which accepts lowercase letters, digits and "
                "underscores only."
            )

        whole_words = bool(options.get("whole_words", True))
        diacritics = bool(options.get("fold_diacritics", False))

        haystack = fold(text, diacritics=diacritics)
        needles = tuple(fold_text(term, diacritics=diacritics) for term in terms)

        return [
            Finding(
                detector_id=self.id,
                tier=self.tier,
                label=label,
                # 1.0. A term either appears or it does not, and there is no model here
                # to be uncertain. Reporting 0.8 would invite a threshold that means
                # nothing.
                score=1.0,
                span=(start, end),
                action=cfg.on_fail,
            )
            for start, end, _matched in find_terms(
                haystack, needles, whole_words=whole_words
            )
        ]
