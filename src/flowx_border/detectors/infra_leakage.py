# SPDX-License-Identifier: Apache-2.0
"""T1: infrastructure detail in an answer: private addresses, home directories, hosts.

A stack trace that reaches a user carries more than the error. Measured on 2026-09-30
against the shipped configuration: a trace containing
`/Users/<name>/secrets/config.yaml` and `10.0.4.17:8443` produced nothing but a
spurious `pii:date`. Neither shape is
personal data in the sense `pii` means, and neither is a credential in the sense
`secrets` means, so nothing was looking.

What it reports, one label per kind
-----------------------------------

`private_ip`         RFC 1918, RFC 6598 carrier-grade NAT, and RFC 4193 unique local.
`loopback_ip`        127/8 and ::1.
`link_local_ip`      169.254/16 and fe80::/10.
`metadata_endpoint`  The cloud instance metadata services, by address, by host name and
                     by their distinctive paths. Checked first, so 169.254.169.254 is
                     reported as what it is rather than as one more link-local address.
`user_home_path`     /home/<user>, /Users/<user>, C:\\Users\\<user>, and the rest.
`system_path`        /etc, /var/lib, /var/log, /root, /proc, /opt, /srv and their
                     Windows counterparts, with at least one segment below the root.
`internal_hostname`  Names under suffixes reserved or conventional for private use:
                     .internal, .local, .home.arpa, .localdomain, .corp, .lan and
                     .intranet.

Every kind is a separate label because a policy may reasonably treat them differently:
a metadata endpoint in an answer is close to an SSRF recipe, a loopback address in a
coding answer is usually the product working. `options.kinds` narrows what is reported
and `options.kind_actions` overrides the action per kind, both validated so that a typo
is refused rather than silently switching a check off.

Why this is not `internal_domains`
----------------------------------

`internal_domains` matches hostnames an organisation lists, and with no list it reports
`domains_not_configured` and nothing else. Everything here is defined by an RFC or by
convention rather than by a deployment, so it works for a caller who configured
nothing. The two can fire on the same span when a policy lists a name under one of
these suffixes; they are different claims, "this is yours" against "this is private",
and both are kept. The host-boundary rule is the same one `internal_domains` uses,
imported from there.

`secrets` excludes dotted numbers and paths on purpose, as not credentials, and `pii`
has no address type. Neither overlaps.

What must not fire, and how it is kept from firing
--------------------------------------------------

**Documentation addresses.** RFC 5737's 192.0.2/24, 198.51.100/24, 203.0.113/24 and RFC
3849's 2001:db8::/32 exist to be written in examples, and they are not reported. The
stdlib's `is_private` answers True for all of them, and for 0.0.0.0/8 as well, which is
why the networks are named here rather than read off that property.

**Version numbers.** `10.0.0.1` is a valid private address and a plausible release
number. A four-part number is not reported when a version word is one of the two words
before it or the word after it, in any of the 26 languages: the cue follows the number
in Hungarian, Turkish and Azerbaijani. A version word further away does not suppress,
so "the server at 10.0.0.5 runs version 1.25" is still reported. `v10.0.0.1` never
matches, because an address may not follow a word character.

**Dates and grouped numbers.** Dates have three dotted parts, never four. Octets with a
leading zero are refused by `ipaddress`, which removes `10.000.000.000`, and a number
followed or preceded by a currency is skipped, which removes `10.100.100.100 EUR`. A
dotted run longer than four parts, an OID, is not an address at any offset.

**Paths that are not on a disk.** A path must not follow a word character, a slash, a
dot or a colon, so `https://example.com/home/maria` and `src/etc/x` are not reported.
`file:///home/...` is, because it is a disk. Placeholders such as `/home/<user>`,
`/Users/username` and `C:\\Users\\Public` expose nobody's layout and are skipped.

**Package names and file names.** `com.acme.internal` is a Java package and
`settings.local` a file name. The first is skipped by its reverse-DNS first label, the
second by a short list of configuration stems, and anything followed by another dotted
label, `config.local.php`, is not a host.

Budget is 5 ms at p95 at the reference input: five regex scans, with `ipaddress` called
only on candidates, of which ordinary prose has none.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator
from typing import Final, NamedTuple, get_args

from flowx_border.detectors.base import OUTPUT, Context, DetectorConfig
from flowx_border.detectors.internal_domains import HOST_CHAR
from flowx_border.types import Action, Finding

#: Every label this detector emits, in the order overlapping matches are resolved: when
#: two spans overlap, the earlier kind in this tuple wins. A metadata URL is a metadata
#: endpoint before it is a link-local address, and a path is kept whole rather than
#: split around an address or a host name written inside it.
KINDS: Final[tuple[str, ...]] = (
    "metadata_endpoint",
    "user_home_path",
    "system_path",
    "private_ip",
    "link_local_ip",
    "loopback_ip",
    "internal_hostname",
)

_ACTIONS: Final[frozenset[str]] = frozenset(get_args(Action))

_Net = ipaddress.IPv4Network | ipaddress.IPv6Network


def _nets(*cidrs: str) -> tuple[_Net, ...]:
    return tuple(ipaddress.ip_network(cidr) for cidr in cidrs)


_METADATA_ADDRESSES: Final = frozenset(
    ipaddress.ip_address(a)
    for a in (
        "169.254.169.254",  # AWS, GCP, Azure, OpenStack, Oracle, DigitalOcean
        "169.254.170.2",  # AWS ECS task metadata
        "100.100.100.200",  # Alibaba Cloud
        "fd00:ec2::254",  # AWS IMDS over IPv6
    )
)

#: Checked before the ranges. None of these is in a range below today, so the check is
#: belt and braces, and it is what keeps them out if a range is ever widened.
_DOCUMENTATION: Final = _nets(
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"
)

_RANGES: Final[tuple[tuple[str, tuple[_Net, ...]], ...]] = (
    ("private_ip", _nets("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")),
    ("private_ip", _nets("100.64.0.0/10", "fc00::/7")),
    ("link_local_ip", _nets("169.254.0.0/16", "fe80::/10")),
    ("loopback_ip", _nets("127.0.0.0/8", "::1/128")),
)

_IPV4: Final = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w)(?!\.\d)")

#: Loose on purpose: a candidate is anything with two colons among hex groups, and
#: `ipaddress` decides. A clock time, a MAC address and `std::vector` all reach it and
#: all fail to parse, or parse to `::`, which is in no range here.
_IPV6: Final = re.compile(
    r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])(?!\.\d)"
)

#: Stems of the word for "version" in the 26 languages, plus the English words a
#: release number is introduced by. Matched against the start of a casefolded word, so
#: inflected forms (versiunea, verzióját, sürümünü, wersję) need no list of their own.
_VERSION_STEMS: Final[tuple[str, ...]] = (
    "versi",  # en fr de nl da sv it es ro fi et lt lv az, and versiyon
    "versã",  # pt
    "versao",
    "verz",  # cs sk hr hu sl
    "wersj",  # pl
    "верси",  # bg
    "έκδοσ",  # el
    "εκδοσ",
    "leagan",  # ga
    "verżjon",  # mt
    "verzjon",
    "sürüm",  # tr
    "različic",  # sl
    "release",
    "build",
    "firmware",
    "patch",
)

_WORD: Final = re.compile(r"\w+")

#: A currency beside a dotted number means it is an amount written with thousands
#: separators, not an address. The currencies of the 26 languages and the usual three.
_CURRENCY: Final = (
    r"(?:EUR|USD|GBP|CHF|RON|BGN|CZK|DKK|HUF|PLN|SEK|NOK|TRY|AZN|lei|лв|Kč|zł|kr|Ft"
    r"|€|\$|£|₺|₼)"
)
_CURRENCY_AFTER: Final = re.compile(rf"\s?{_CURRENCY}(?!\w)")
_CURRENCY_BEFORE: Final = re.compile(rf"(?<!\w){_CURRENCY}\s?$")

#: What ends a path: whitespace, quotes, brackets, and the separators prose puts after
#: one. A colon ends it too, so `app.py:42` reports the file and not the line number.
_PATH_TAIL: Final = r"[^\s\"'`<>|:;,()\[\]{}]*"
_SEGMENT: Final = r"[^\s\"'`<>|:;,()\[\]{}/\\]+"

#: Not preceded by anything that would make this part of a URL or a relative path.
#: `file://` is the exception, because a file URL names a disk.
_PATH_START: Final = r"(?:(?<=file://)|(?<![\w/\\.:~-]))"

_POSIX_HOME: Final = re.compile(
    rf"{_PATH_START}/(?:home|Users)/(?P<user>{_SEGMENT}){_PATH_TAIL}"
)
_WINDOWS_HOME: Final = re.compile(
    rf"(?<![\w\\/])(?i:[a-z]:[\\/]+(?:users|documents and settings)[\\/]+)"
    rf"(?P<user>{_SEGMENT}){_PATH_TAIL}"
)
_POSIX_SYSTEM: Final = re.compile(
    rf"{_PATH_START}/(?:etc|root|proc|opt|srv|usr/local|private/(?:etc|var)"
    rf"|var/(?:lib|log|run|spool|www|backups|cache|opt))/{_SEGMENT}{_PATH_TAIL}"
)
_WINDOWS_SYSTEM: Final = re.compile(
    rf"(?<![\w\\/])(?i:[a-z]:[\\/]+(?:windows|programdata|inetpub)[\\/]+)"
    rf"{_SEGMENT}{_PATH_TAIL}"
)

#: User segments that are a template rather than somebody's account. `user` is on the
#: list although it is a real account name on many container images, because in text it
#: is overwhelmingly the placeholder, and a false positive on every tutorial costs more
#: than the rare real one.
#:
#: The word for "user" in each of the 26 languages is here too. Found on 2026-09-30 in
#: the politeness corpus, where a Spanish answer explained paths with
#: `/home/usuario/archivo.txt`: a tutorial written in Spanish uses the Spanish word.
_PLACEHOLDER_USERS: Final = frozenset(
    {
        # The word for "user", by language.
        "usuario",  # es
        "usuário",  # pt
        "utilizador",
        "utilisateur",  # fr
        "benutzer",  # de
        "nutzer",
        "utente",  # it
        "utilizator",  # ro
        "gebruiker",  # nl
        "bruger",  # da
        "användare",  # sv
        "anvandare",
        "käyttäjä",  # fi
        "kayttaja",
        "kasutaja",  # et
        "użytkownik",  # pl
        "uzytkownik",
        "uživatel",  # cs
        "uzivatel",
        "používateľ",  # sk
        "pouzivatel",
        "felhasználó",  # hu
        "felhasznalo",
        "korisnik",  # hr
        "uporabnik",  # sl
        "naudotojas",  # lt
        "vartotojas",
        "lietotājs",  # lv
        "lietotajs",
        "utent",  # mt
        "úsáideoir",  # ga
        "usaideoir",
        "kullanıcı",  # tr
        "kullanici",
        "istifadəçi",  # az
        "istifadeci",
        "потребител",  # bg
        "χρήστης",  # el
        "χρηστης",
        # English and generic.
        "user",
        "username",
        "user_name",
        "user-name",
        "yourname",
        "your_name",
        "your-name",
        "yourusername",
        "your_username",
        "you",
        "me",
        "name",
        "example",
        "someone",
        "public",
        "shared",
        "default",
        "all users",
        "...",
        "…",
        "*",
    }
)

_METADATA_TEXT: Final = re.compile(
    r"(?<![\w.-])(?i:metadata\.google\.internal|metadata\.goog)(?![\w-])(?!\.\w)"
    r"|/latest/(?:meta-data|user-data|dynamic/instance-identity)(?![\w-])"
    r"|/computeMetadata/v1(?!\w)"
    r"|/metadata/instance(?![\w-])"
)

_HOSTNAME: Final = re.compile(
    rf"(?<!{HOST_CHAR})(?<!\.)(?i:(?P<first>[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?)\."
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"(?P<suffix>localdomain|local|internal|home\.arpa|corp|lan|intranet))"
    rf"(?!{HOST_CHAR})(?!\.{HOST_CHAR})"
)

#: First labels that make a dotted name a package rather than a host.
_PACKAGE_ROOTS: Final = frozenset(
    {
        "com",
        "org",
        "net",
        "io",
        "java",
        "javax",
        "android",
        "androidx",
        "kotlin",
        "sun",
        "jdk",
        "scala",
        "edu",
        "gov",
    }
)

#: First labels that make `<x>.local` a configuration file rather than an mDNS host.
_FILE_STEMS: Final = frozenset(
    {
        "env",
        "settings",
        "config",
        "configuration",
        "appsettings",
        "application",
        "compose",
        "docker-compose",
        "vite",
        "webpack",
        "next",
        "values",
        "local",
    }
)


class _Hit(NamedTuple):
    start: int
    end: int
    kind: str


def _version_cue(text: str, start: int, end: int) -> bool:
    before = _WORD.findall(text[max(0, start - 40) : start].casefold())[-2:]
    tail = text[end : end + 40]
    after = _WORD.findall(tail.casefold())
    # `10.0.0.1-es verzió`: the Hungarian case suffix is its own token and the version
    # word is the one after it.
    if tail.startswith("-") and after:
        after = after[1:]
    words = [*before, *after[:1]]
    return any(word.startswith(_VERSION_STEMS) for word in words)


def _address_kind(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> str | None:
    if address in _METADATA_ADDRESSES:
        return "metadata_endpoint"
    if any(address in net for net in _DOCUMENTATION):
        return None
    for kind, nets in _RANGES:
        if any(address in net for net in nets):
            return kind
    return None


def _addresses(text: str) -> Iterator[_Hit]:
    for match in _IPV4.finditer(text):
        try:
            address = ipaddress.IPv4Address(match.group())
        except ValueError:
            continue
        kind = _address_kind(address)
        if kind is None:
            continue
        start, end = match.span()
        if _CURRENCY_AFTER.match(text, end) or _CURRENCY_BEFORE.search(
            text[max(0, start - 6) : start]
        ):
            continue
        if _version_cue(text, start, end):
            continue
        yield _Hit(start, end, kind)

    for match in _IPV6.finditer(text):
        try:
            address6 = ipaddress.IPv6Address(match.group())
        except ValueError:
            continue
        kind = _address_kind(address6)
        if kind is not None:
            yield _Hit(match.start(), match.end(), kind)


def _trimmed(text: str, start: int, end: int) -> int:
    """The end of a path with the sentence's closing punctuation taken off."""
    while end > start and text[end - 1] in ".,!?":
        end -= 1
    return end


def _is_placeholder(user: str) -> bool:
    user = user.rstrip(".,;:!?'\"’”»")
    return not user or user.casefold() in _PLACEHOLDER_USERS or user[0] in "<{$%[~*"


def _paths(text: str) -> Iterator[_Hit]:
    for pattern in (_POSIX_HOME, _WINDOWS_HOME):
        for match in pattern.finditer(text):
            if _is_placeholder(match.group("user")):
                continue
            start = match.start()
            yield _Hit(start, _trimmed(text, start, match.end()), "user_home_path")
    for pattern in (_POSIX_SYSTEM, _WINDOWS_SYSTEM):
        for match in pattern.finditer(text):
            start = match.start()
            yield _Hit(start, _trimmed(text, start, match.end()), "system_path")


def _hosts(text: str) -> Iterator[_Hit]:
    for match in _METADATA_TEXT.finditer(text):
        yield _Hit(match.start(), match.end(), "metadata_endpoint")
    for match in _HOSTNAME.finditer(text):
        first = match.group("first").casefold()
        if first in _PACKAGE_ROOTS:
            continue
        if match.group("suffix").casefold() == "local" and first in _FILE_STEMS:
            continue
        yield _Hit(match.start(), match.end(), "internal_hostname")


def _resolve(hits: list[_Hit]) -> list[_Hit]:
    """One finding per stretch of text, the most specific kind winning.

    Greedy by kind order and then by length, which is enough because the kinds are few
    and a real overlap is a path containing an address or a URL containing a host.
    """
    rank = {kind: index for index, kind in enumerate(KINDS)}
    kept: list[_Hit] = []
    for hit in sorted(hits, key=lambda h: (rank[h.kind], h.start - h.end)):
        if all(hit.end <= k.start or hit.start >= k.end for k in kept):
            kept.append(hit)
    return sorted(kept)


def _kinds(cfg: DetectorConfig) -> frozenset[str]:
    raw = cfg.options.get("kinds")
    if raw is None:
        return frozenset(KINDS)
    if isinstance(raw, str):
        raw = [raw]
    wanted = frozenset(str(kind).strip().lower() for kind in raw)
    unknown = sorted(wanted - set(KINDS))
    if unknown:
        raise ValueError(
            f"infra_leakage: kinds names unknown kinds {unknown}. Known kinds are "
            f"{list(KINDS)}. A misspelled kind would silently switch a check off."
        )
    return wanted


def _kind_actions(cfg: DetectorConfig) -> dict[str, Action]:
    raw = cfg.options.get("kind_actions")
    if not raw:
        return {}
    if not isinstance(raw, dict):
        raise ValueError(
            "infra_leakage: kind_actions must be a mapping of kind to action, for "
            "example {loopback_ip: log}."
        )
    out: dict[str, Action] = {}
    for name, action in raw.items():
        kind = str(name).strip().lower()
        if kind not in KINDS:
            raise ValueError(
                f"infra_leakage: kind_actions names unknown kind {kind!r}. Known kinds "
                f"are {list(KINDS)}."
            )
        chosen = str(action).strip().lower()
        if chosen not in _ACTIONS:
            raise ValueError(
                f"infra_leakage: kind_actions gives {kind!r} the action {chosen!r}, "
                f"which is not one of {sorted(_ACTIONS)}."
            )
        out[kind] = chosen  # type: ignore[assignment]
    return out


class InfraLeakageDetector:
    """Reports private addresses, home and system paths, and private host names."""

    id = "infra_leakage"
    tier = "T1"
    sides = frozenset({OUTPUT})

    def warm(self) -> None:
        """Nothing to load. The patterns compile at import."""

    def run(
        self,
        text: str,
        cfg: DetectorConfig,
        ctx: Context,  # noqa: ARG002 - the Detector protocol fixes this signature
    ) -> list[Finding]:
        wanted = _kinds(cfg)
        actions = _kind_actions(cfg)
        hits = [
            hit
            for hit in (*_addresses(text), *_paths(text), *_hosts(text))
            if hit.kind in wanted
        ]
        return [
            Finding(
                detector_id=self.id,
                tier=self.tier,
                label=hit.kind,
                # 1.0: the shape is in a reserved range or under a reserved root, or it
                # is not. The judgement is in what was excluded above, not in a score.
                score=1.0,
                span=(hit.start, hit.end),
                action=actions.get(hit.kind, cfg.on_fail),
            )
            for hit in _resolve(hits)
        ]
