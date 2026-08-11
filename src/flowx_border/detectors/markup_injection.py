# SPDX-License-Identifier: Apache-2.0
"""T1: markup in the text that a browser would execute rather than display.

Ported from the Guardrails Hub `web_sanitization` validator, which is one line:
`bleach.clean(value) != value`. That is a sanitiser used as a detector, and the two
want opposite things.

Why the original reports an attack in ordinary prose
-----------------------------------------------------

`bleach.clean` escapes every character that is special in HTML, so it changes the
string whenever the text contains `<`, `>` or `&` for any reason at all. `5 < 6 and 7 >
3` comes back as `5 &lt; 6 and 7 &gt; 3`, which differs from the input, so the validator
reports a web injection attack. So does a Danish price written `Pris & moms`, so does a
mathematical answer, so does any answer that mentions an HTML tag by name. In a
26-language deployment this is worse rather than better: `&` and comparison operators
are not less common in Greek or Finnish, and a check that fires on ordinary text gets
switched off, which leaves the real payload undetected.

This port names the vectors instead. It fires on markup that executes, and it does not
fire on markup that merely exists, so `5 < 6` is clean and `<img src=x onerror=...>` is
not. That is a narrower claim than "this text is safe to put in a page", and it is a
claim the detector can actually support. Escaping output before it reaches a browser is
still the caller's job; no detector replaces it.

The evasions it folds away first
--------------------------------

All matching happens on text folded by multilingual.py with compatibility
normalisation and HTML character references decoded, which is what makes the following
one string rather than five:

    <script>              plain
    <SCRIPT>              case, folded
    <scr<U+200B>ipt>      zero-width character, dropped
    &#60;script&#62;      numeric references, decoded
    ｊａｖａｓｃｒｉｐｔ:   full-width Latin, folded by NFKC

The last one is the reason compatibility normalisation is on here and off for prose. A
browser resolves full-width characters in a URL scheme; a reader of Romanian text does
not want ﬁ split into fi. Same function, different setting, stated at the call site.

Note that `&lt;script&gt;` folds to `<script>` and is reported. That is deliberate: it
is the encoded spelling of the payload, and whether it stays inert depends on how many
times the consuming template unescapes, which this library cannot see. Reporting it and
letting the policy decide beats guessing.

Both sides, for different reasons
---------------------------------

On the output side this is the classic case: the model emits markup, the product puts
it in a page, the user's browser runs it. On the input side it is a payload arriving,
which matters because a model that echoes its input has just laundered it through your
product. Neither side is the more important one, so both are on and a policy narrows it.

Budget is 5 ms at p95 at the reference input: one folding pass and one alternation.
"""

from __future__ import annotations

import re
from typing import Final

from flowx_border.detectors.base import INPUT, OUTPUT, Context, DetectorConfig
from flowx_border.detectors.multilingual import fold
from flowx_border.types import Finding

#: Vectors, each named so an evidence record says which one was found rather than only
#: that something was. Applied to folded text, so none of them needs a case-insensitive
#: flag or an alternation over spellings.
#:
#: Deliberately absent, each because it fires on text a working product produces:
#:   - a bare `<svg>` or `<style>`. Dangerous only with a handler or a script inside,
#:     and both of those are caught by their own rule below.
#:   - `expression(` , the obsolete IE CSS vector, which collides with prose about
#:     mathematical expressions in every language here.
#:   - any rule that fires on `<` alone. That is the upstream behaviour this file
#:     exists to replace.
#:
#: Every rule that starts at a `<` runs to the end of that tag, `[^<>]*>?`, rather than
#: stopping at the tag name. The detection is the same either way, because `<script` is
#: already conclusive. The difference is what redaction produces: a span covering only
#: `<script` leaves `>alert(1)` in the text, which is inert but reads as though
#: something was missed, and a span covering `<script>` leaves the answer clean. The `>`
#: is optional so an unterminated tag at the end of a truncated output still matches.
_TAG_TAIL: Final = r"[^<>]*>?"

#: Ordered most specific first, and the order is load-bearing rather than cosmetic. One
#: payload frequently matches two rules over the same text, `<iframe srcdoc=...>` being
#: the standing example, and `run` keeps whichever claims the span first. Listing
#: `iframe_element` before `srcdoc_attribute` would report the tag and lose the reason
#: it is dangerous, which is the more useful half for whoever reads the record.
_VECTORS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("script_element", re.compile(rf"<\s*/?\s*script\b{_TAG_TAIL}")),
    # Anchored on an opening tag, so `onerror=` only counts inside one. Without the
    # anchor a query string like `?online=1` matches `on` plus four letters and every
    # URL in the text becomes a finding.
    (
        "event_handler",
        re.compile(rf"<[a-z][a-z0-9]*(?:\s[^<>]*)?\son[a-z]{{2,20}}\s*={_TAG_TAIL}"),
    ),
    (
        "srcdoc_attribute",
        re.compile(rf"<[a-z][a-z0-9]*(?:\s[^<>]*)?\ssrcdoc\s*={_TAG_TAIL}"),
    ),
    (
        "meta_refresh",
        re.compile(rf"<\s*meta\b[^<>]*http-equiv\s*=\s*[\"']?\s*refresh{_TAG_TAIL}"),
    ),
    # The optional space absorbs `java&#9;script:`, which decodes to a tab and folds to
    # a space. Browsers strip whitespace inside a scheme, so this spelling runs.
    #
    # These three do not take the tag tail: they match inside an attribute value, and
    # neutralising the scheme is what makes the URL inert. Swallowing the rest of the
    # tag would redact the href of a link that is otherwise fine.
    ("javascript_url", re.compile(r"\bjava\s?script\s*:")),
    ("vbscript_url", re.compile(r"\bvbscript\s*:")),
    ("data_url_html", re.compile(r"\bdata\s*:\s*text/html")),
    # The generic element rules come last: they say a dangerous tag is present, and any
    # rule above says why.
    ("iframe_element", re.compile(rf"<\s*iframe\b{_TAG_TAIL}")),
    ("object_element", re.compile(rf"<\s*(?:object|embed)\b{_TAG_TAIL}")),
)


class MarkupInjectionDetector:
    """Named browser-execution vectors, over folded and entity-decoded text."""

    id = "markup_injection"
    tier = "T1"
    sides = frozenset({INPUT, OUTPUT})

    def warm(self) -> None:
        """Nothing to load. Patterns compile at import, so this is a no-op.

        Present because the protocol requires it, and because a caller warming every
        detector should not have to know which ones have weights.
        """

    def run(
        self,
        text: str,
        cfg: DetectorConfig,
        ctx: Context,  # noqa: ARG002 - the Detector protocol fixes this signature
    ) -> list[Finding]:
        haystack = fold(text, compat=True, entities=True)

        out: list[Finding] = []
        claimed: list[tuple[int, int]] = []
        for label, pattern in _VECTORS:
            for match in pattern.finditer(haystack.text):
                start, end = haystack.span(match.start(), match.end())
                # `<script src=x onerror=y>` matches two rules over overlapping text.
                # One payload should be one finding, and the first rule to claim it is
                # the more specific one by the ordering above.
                if any(start >= s and end <= e for s, e in claimed):
                    continue
                claimed.append((start, end))
                out.append(
                    Finding(
                        detector_id=self.id,
                        tier=self.tier,
                        label=label,
                        # 1.0. Each rule names a construct that executes; there is no
                        # judgement being made about how likely that is.
                        score=1.0,
                        span=(start, end),
                        action=cfg.on_fail,
                    )
                )
        return out
