# SPDX-License-Identifier: Apache-2.0
"""T1: links in the answer that do not go where they say they go.

`[bank.example](https://evil.test/login)` passes every other detector here.
`markup_injection` asks whether markup executes, and a plain link does not.
`url_reachability` asks whether a link answers, and an attacker's page answers fine.
`internal_domains` asks whether a host is on the caller's list, and neither host is.
None of them asks whether the link says what it does, which is the question a phishing
link fails. This one asks it, with rules, without the network.

What it reports, one finding per link
-------------------------------------

`link_userinfo`
    The target carries userinfo: `https://bank.example@evil.test/` goes to `evil.test`,
    and everything before the `@` is a user name the reader takes for a host. It also
    catches `https://user:password@host/`, which is a credential in an answer. Nobody
    links a reader to a page with either on purpose.

`link_confusable_host`
    The target host mixes scripts inside one label, `p` + Cyrillic `а` + `ypal.com`, or
    is written entirely in Cyrillic or Greek letters that each look like a Latin one,
    under an ASCII top-level domain. Punycode labels are decoded first, so
    `xn--pypal-4ve.com` is the same finding, and a label that will not decode is one
    too: a host nobody can read is not one a reader can check.

`link_ip_host`
    The target is an IP literal, including the integer and hex spellings browsers still
    resolve (`http://3232235777/`, `http://0x7f.0.0.1/`). A bank's answer has no reason
    to send a customer to an address rather than a name. Loopback written the ordinary
    way, `127.0.0.1` or `::1`, is exempt: it is the reader's own machine, there is no
    third party to hand them to, and every framework's quickstart links to it. Private
    ranges are not exempt, because a policy that serves router instructions can say so
    and one that does not should hear about them.

`link_text_mismatch`
    The visible text is itself a URL or a hostname, and its registrable domain is not
    the target's. `[docs.python.org](https://python.org/docs)` is fine, one site;
    `[bank.example](https://bank.example.evil.test/)` is not.

When several apply, the first in that order is reported, because it names the trick
rather than the symptom. The span covers the whole link, so a redaction removes the
link and its text together rather than leaving a trusted name pointing nowhere.

The 26 languages, and why an IDN host is not a finding by itself
----------------------------------------------------------------

Flagging every internationalised host would be simple and wrong for this library.
`münchen.example`, `łódź.example.pl`, a Bulgarian address under `.бг` and a Greek one
under `.ελ` are ordinary in the languages this project claims, and a detector that
fires on them is switched off by exactly the deployments it should protect. So the
default is the rule browsers converged on: a label in one script is that script's
business, and what gets reported is a label that mixes scripts, or a whole-script
lookalike of Latin under a Latin TLD. A policy that wants every non-ASCII host
reported sets `idn_hosts: all`, and gets `link_idn_host` for the ones that are not
confusable.

Deciding that the visible text names a host
-------------------------------------------

Only when the whole anchor text is a URL or a hostname. `[Log in at bank.example]` is
prose, and guessing which word is the claim invites more false positives than it
catches. For a scheme-less name the top-level domain must be in the IANA root zone
list, shipped as `data/iana_tlds.txt` (version line at its head, refreshed by hand),
plus the four names RFC 2606 reserves, so `Node.js` and `v1.2` are not hosts. Without
a scheme or `www.`, a small set of TLDs that collide with file extensions is also
refused: `README.md`, `main.rs`, `setup.py`
name files far more often than Moldovan, Serbian or Paraguayan sites. `.pl` is not in
that set, because Polish is one of the 26 and Perl is rare here.

The registrable-domain rule is a heuristic, and which one
---------------------------------------------------------

There is no network and no Public Suffix List download. The registrable domain is the
last two labels, or the last three when the last two are a multi-part public suffix in
`_MULTI_PART_SUFFIXES`, a hand-picked subset of the ICANN section of the Public Suffix
List (https://publicsuffix.org/list/public_suffix_list.dat) weighted to the countries
the 26 languages are spoken in. The subset errs in one direction only: a suffix missing
from it makes two different sites under, say, `com.xx` compare equal, which is a missed
finding and never a false one.

What it does not cover
----------------------

Anchor text that names a brand rather than a host, the proposal's own `[your bank]`
example, cannot be judged by a rule: nothing in the text says which host is the bank's.
That half needs `internal_domains`-style configuration or a model, and is left out
rather than guessed. Shortcut reference links, `[text]` with no second bracket, are
not parsed because they are indistinguishable from bracketed prose.

Budget is 5 ms at p95 at the reference input: one folding pass and four patterns.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Final

from flowx_border.detectors.base import OUTPUT, Context, DetectorConfig
from flowx_border.detectors.multilingual import fold
from flowx_border.types import Finding

_TLD_FILE: Final = Path(__file__).resolve().parent.parent / "data" / "iana_tlds.txt"

#: Schemes whose links carry a host a reader is asked to trust. `mailto:` and `tel:`
#: have no host in this sense, and `javascript:` is markup_injection's question.
_WEB_SCHEMES: Final = frozenset({"http", "https", "ftp"})

#: TLDs that are also common file extensions. Refused for scheme-less anchor text that
#: does not start with `www.`, so a filename is not read as a host. Each one is a real
#: TLD, which is why this has to be a list rather than falling out of the IANA check.
_FILENAME_TLDS: Final = frozenset(
    {"md", "py", "rs", "sh", "cc", "so", "pm", "zip", "mov"}
)

#: Multi-part public suffixes: a subset of the ICANN section of the Public Suffix List,
#: https://publicsuffix.org/list/public_suffix_list.dat, read 2026-09-30. Weighted to
#: the 26 languages' countries plus the handful that recur in any corpus. A missing
#: entry costs a missed finding, never a false one; see the module docstring.
_MULTI_PART_SUFFIXES: Final = frozenset(
    {
        # United Kingdom, Ireland, Malta, Cyprus
        *("co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "ac.uk"),
        *("gov.uk", "nhs.uk", "police.uk", "sch.uk", "gov.ie"),
        *("com.mt", "org.mt", "net.mt", "edu.mt", "gov.mt"),
        *("com.cy", "org.cy", "net.cy", "gov.cy", "ac.cy"),
        # Greece, Turkey, Azerbaijan
        *("com.gr", "org.gr", "net.gr", "edu.gr", "gov.gr"),
        *("com.tr", "org.tr", "net.tr", "edu.tr", "gov.tr", "gen.tr", "biz.tr"),
        *("info.tr", "av.tr", "bel.tr", "k12.tr"),
        *("com.az", "net.az", "org.az", "gov.az", "edu.az", "int.az", "biz.az"),
        "info.az",
        # Romania, Poland, Hungary, Austria
        *("com.ro", "org.ro", "info.ro", "nom.ro", "nt.ro", "rec.ro", "store.ro"),
        *("tm.ro", "firm.ro", "www.ro", "arts.ro"),
        *("com.pl", "net.pl", "org.pl", "info.pl", "biz.pl", "gov.pl", "edu.pl"),
        *("co.hu", "org.hu", "info.hu", "tm.hu"),
        *("co.at", "or.at", "ac.at", "gv.at"),
        # Spain, Portugal, France, Italy, Belgium, Croatia, Latvia
        *("com.es", "org.es", "nom.es", "gob.es", "edu.es"),
        *("com.pt", "org.pt", "gov.pt", "edu.pt"),
        *("asso.fr", "com.fr", "gouv.fr", "nom.fr"),
        *("gov.it", "edu.it", "ac.be"),
        *("com.hr", "from.hr", "iz.hr", "name.hr"),
        *("com.lv", "org.lv", "gov.lv", "edu.lv", "id.lv", "net.lv"),
        # Recurring elsewhere
        *("com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au"),
        *("co.nz", "net.nz", "org.nz", "govt.nz"),
        *("co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp"),
        *("com.br", "net.br", "org.br", "gov.br"),
        *("co.za", "org.za", "gov.za"),
        *("com.cn", "net.cn", "org.cn", "gov.cn"),
        *("co.in", "net.in", "org.in", "gov.in", "ac.in"),
        *("co.il", "org.il", "ac.il", "gov.il"),
        *("com.mx", "org.mx", "gob.mx", "com.ar", "com.sg", "gov.sg", "com.hk"),
        *("co.kr", "or.kr", "com.tw", "com.ua", "gov.ua", "org.ua"),
    }
)

#: Cyrillic and Greek lowercase letters that render as a Latin one in common fonts.
#: A label made only of these, under an ASCII TLD, is a whole-script lookalike.
_LATIN_LOOKALIKES: Final = frozenset(
    "аеорсухіјѕ"  # а е о р с у х і ј ѕ
    "ԁӏһԛԝү"  # ԁ ӏ һ ԛ ԝ ү
    "οανρικυ"  # ο α ν ρ ι κ υ
)

#: Scripts that are written together in one label by design, folded to one group.
_SCRIPT_GROUPS: Final = {"HIRAGANA": "HAN", "KATAKANA": "HAN", "CJK": "HAN"}

#: Numeric host spellings that are not dotted quads but still resolve: `3232235777`,
#: `0x7f.0.0.1`, `127.1`. ipaddress rejects them; browsers do not.
_NUMERIC_HOST: Final = re.compile(
    r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}"
)

#: `[text](href "title")`, not preceded by `!`, which would make it an image. The href
#: allows one level of balanced parentheses, which is how Wikipedia URLs are written.
_MD_INLINE: Final = re.compile(
    r"(?<!!)\[([^\[\]]*)\]\(\s*"
    r"(?:<([^<>]*)>|((?:[^\s()]|\([^\s()]*\))+))"
    r"(?:\s+(?:\"[^\"]*\"|'[^']*'|\([^()]*\)))?\s*\)"
)

#: `[text][id]`, and `[text][]` meaning the id is the text.
_MD_REF_USE: Final = re.compile(r"(?<!!)\[([^\[\]]+)\]\[([^\[\]]*)\]")

#: `[id]: href`. Folded text has no newlines, so this anchors on whitespace or the
#: start of the text rather than on `^`.
_MD_REF_DEF: Final = re.compile(r"(?:^|(?<=\s))\[([^\[\]]+)\]:\s*<?([^\s<>]+)>?")

_HTML_A: Final = re.compile(
    r"<a\b[^<>]*?\bhref\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s\"'<>]+))[^<>]*>"
    r"(.*?)</a\s*>",
    re.DOTALL,
)
_TAG: Final = re.compile(r"<[^<>]*>")

#: URLs in prose, which most renderers turn into links whether or not they were
#: written as one. Same shape as url_reachability's pattern.
_BARE_URL: Final = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`]+")

#: Characters that end a sentence rather than a URL.
_TRAILING: Final = ".,;:!?)]}'\"»”’"

#: Wrapping that turns a hostname into emphasis or code without changing what it names.
_ANCHOR_WRAP: Final = "*_`'\"<> "

#: A scheme-less hostname, optionally with a port and a path. Labels are Unicode word
#: characters and hyphens, so an internationalised name is one.
_BARE_HOST: Final = re.compile(r"([\w-]+(?:\.[\w-]+)+)\.?(?::[0-9]{1,5})?(?:[/?#]\S*)?")

_IDN_MODES: Final = ("confusable", "all")


#: The names RFC 2606 reserves for documentation and testing. Not in the root zone,
#: and still hosts in every sense that matters here: an answer quoting its own
#: examples writes `bank.example`, and a test suite does too.
_RESERVED_TLDS: Final = frozenset({"example", "test", "invalid", "localhost"})


@lru_cache(maxsize=1)
def _tlds() -> frozenset[str]:
    """The IANA root zone, lowercased, punycode spellings as IANA writes them."""
    return _RESERVED_TLDS | frozenset(
        line.strip().casefold()
        for line in _TLD_FILE.read_text(encoding="ascii").splitlines()
        if line.strip() and not line.startswith("#")
    )


def _to_ascii(label: str) -> str:
    """One label in its punycode spelling, or as written if the codec refuses it."""
    try:
        return label.encode("idna").decode("ascii")
    except UnicodeError:
        return label


def _is_ip(host: str) -> bool:
    """An IP literal in any spelling a browser resolves, for a target host."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return _NUMERIC_HOST.fullmatch(host) is not None
    return True


def _is_canonical_ip(host: str) -> bool:
    """An IP literal written the standard way, for visible text.

    Stricter than `_is_ip` on purpose. In prose `3.4.9` is a version number far more
    often than an address, and a changelog links every one of them.
    """
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _normalise(host: str) -> str:
    return host.rstrip(".").casefold()


def registrable_domain(host: str) -> str:
    """The part of a host one party registers, by the heuristic the docstring names.

    Returned in punycode so the two spellings of one internationalised name compare
    equal. An IP literal is its own registrable domain.
    """
    host = _normalise(host)
    if _is_ip(host):
        return host
    labels = [_to_ascii(label) for label in host.split(".")]
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _script(char: str) -> str | None:
    """The script a letter belongs to, or None for anything that is not a letter."""
    if not char.isalpha():
        return None
    if char.isascii():
        return "LATIN"
    first = unicodedata.name(char, "UNKNOWN").split(" ", 1)[0]
    return _SCRIPT_GROUPS.get(first, first)


def _unicode_labels(host: str) -> list[str] | None:
    """Labels with punycode decoded. None when a punycode label will not decode."""
    out: list[str] = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                out.append(label.encode("ascii").decode("idna"))
            except UnicodeError:
                return None
        else:
            out.append(label)
    return out


def _is_confusable(host: str) -> bool:
    labels = _unicode_labels(host)
    if labels is None:
        return True
    ascii_tld = bool(labels) and labels[-1].isascii()
    for label in labels:
        scripts = {s for s in map(_script, label) if s is not None}
        if len(scripts) > 1:
            return True
        if (
            ascii_tld
            and scripts & {"CYRILLIC", "GREEK"}
            and all(c in _LATIN_LOOKALIKES for c in label if c.isalpha())
        ):
            return True
    return False


def _is_idn(host: str) -> bool:
    return not host.isascii() or any(
        label.startswith("xn--") for label in host.split(".")
    )


def _named_host(anchor: str) -> str | None:
    """The host the visible text names, when the whole of it is a URL or hostname."""
    text = _TAG.sub("", anchor).strip(_ANCHOR_WRAP).rstrip(_TRAILING)
    if not text or any(char.isspace() for char in text):
        return None
    scheme, sep, _ = text.partition("://")
    if sep:
        if scheme not in _WEB_SCHEMES:
            return None
        try:
            host = urllib.parse.urlsplit(text).hostname
        except ValueError:
            return None
        return _normalise(host) if host else None

    match = _BARE_HOST.fullmatch(text)
    if match is None:
        return None
    host = _normalise(match.group(1))
    if _is_canonical_ip(host):
        return host
    tld = _to_ascii(host.rsplit(".", 1)[-1])
    if tld not in _tlds():
        return None
    if tld in _FILENAME_TLDS and not host.startswith("www."):
        return None
    return host


@dataclass(frozen=True)
class _Target:
    host: str
    userinfo: bool


def _target(href: str) -> _Target | None:
    """The host a link goes to, or None for a relative or non-web link."""
    try:
        parts = urllib.parse.urlsplit(href.strip())
        host = parts.hostname
    except ValueError:
        return None
    if parts.scheme not in _WEB_SCHEMES or not host:
        return None
    return _Target(host=_normalise(host), userinfo="@" in parts.netloc)


@dataclass(frozen=True)
class _Link:
    start: int
    end: int
    href: str
    anchor: str | None


class LinkIntegrityDetector:
    """Reports links whose target is not what the reader is shown."""

    id = "link_integrity"
    tier = "T1"
    sides = frozenset({OUTPUT})

    def warm(self) -> None:
        """Read the TLD list, so the first scan does not pay for the file."""
        _tlds()

    def run(
        self,
        text: str,
        cfg: DetectorConfig,
        ctx: Context,  # noqa: ARG002 - the Detector protocol fixes this signature
    ) -> list[Finding]:
        idn_mode = str(cfg.options.get("idn_hosts", "confusable"))
        if idn_mode not in _IDN_MODES:
            # Refused rather than defaulted: a typo here would quietly turn the check a
            # policy asked for into a narrower one.
            raise ValueError(
                f"link_integrity: idn_hosts must be one of {_IDN_MODES}, "
                f"got {idn_mode!r}"
            )

        # Compatibility folding and entity decoding for the reason markup_injection
        # gives: a browser resolves `&#64;` and full-width letters in a URL, so the
        # detector has to see what the browser sees.
        haystack = fold(text, compat=True, entities=True)
        out: list[Finding] = []
        for link in _links(haystack.text):
            label = _judge(link, idn_mode)
            if label is None:
                continue
            out.append(
                Finding(
                    detector_id=self.id,
                    tier=self.tier,
                    label=label,
                    # 1.0. Each rule is a fact about the link, not an estimate.
                    score=1.0,
                    span=haystack.span(link.start, link.end),
                    action=cfg.on_fail,
                )
            )
        return out


def _judge(link: _Link, idn_mode: str) -> str | None:
    target = _target(link.href)
    if target is None:
        return None
    if target.userinfo:
        return "link_userinfo"
    if _is_confusable(target.host):
        return "link_confusable_host"
    if idn_mode == "all" and _is_idn(target.host):
        return "link_idn_host"
    if _is_ip(target.host) and not _is_loopback(target.host):
        return "link_ip_host"
    if link.anchor is not None:
        named = _named_host(link.anchor)
        if named is not None and registrable_domain(named) != registrable_domain(
            target.host
        ):
            return "link_text_mismatch"
    return None


def _links(text: str) -> list[_Link]:
    """Every link in folded text: Markdown, HTML, then bare URLs nobody else claimed."""
    links: list[_Link] = []
    claimed: list[tuple[int, int]] = []

    definitions: dict[str, str] = {}
    for match in _MD_REF_DEF.finditer(text):
        definitions.setdefault(match.group(1).strip(), match.group(2))
        # A definition is invisible once rendered, so its URL is not a link on its own.
        claimed.append(match.span())

    for match in _MD_INLINE.finditer(text):
        href = match.group(2) if match.group(2) is not None else match.group(3)
        links.append(_Link(match.start(), match.end(), href, match.group(1)))
        claimed.append(match.span())

    for match in _MD_REF_USE.finditer(text):
        ref = (match.group(2) or match.group(1)).strip()
        if ref in definitions:
            links.append(
                _Link(match.start(), match.end(), definitions[ref], match.group(1))
            )
            claimed.append(match.span())

    for match in _HTML_A.finditer(text):
        href = next(group for group in match.groups()[:3] if group is not None)
        links.append(_Link(match.start(), match.end(), href, match.group(4)))
        claimed.append(match.span())

    for match in _BARE_URL.finditer(text):
        start, end = match.start(), match.end()
        if any(start < e and end > s for s, e in claimed):
            continue
        url = match.group().rstrip(_TRAILING)
        links.append(_Link(start, start + len(url), url, None))

    links.sort(key=lambda link: link.start)
    return links
