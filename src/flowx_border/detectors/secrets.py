# SPDX-License-Identifier: Apache-2.0
"""T0: credentials in the text on its way to the model.

Two rules, in this order, and the order is the design.

**Named patterns.** Credential formats that identify themselves: `AKIA...`, `ghp_...`,
`sk-ant-api03-...`, a PEM header. These are the ones worth blocking on, because a match
is a credential and not a guess. Score 1.0.

**Entropy.** A token that looks random and is long enough to be a secret. This is the
rule that catches the key format nobody has heard of, and it is also the rule that will
produce every false positive this detector ever produces. So it is deliberately
timid: see `_entropy_findings` for what it refuses to fire on, and why.

Why the timidity matters here more than anywhere else. The shipped default policy sets
`secrets: on_fail: block`, T0 cannot be disabled, and `secrets` is the first detector to
run on the input side. A false positive is not a noisy log line, it is a refused request
that the user cannot get around. A UUID in a support ticket must not be a blocked
request, so a UUID is not a secret here even though it is high entropy.

Budget is 1 ms at p95. Everything is compiled once at import, both rules are a single
pass, and there is no backtracking construct in any pattern.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Final

from flowx_border.detectors.base import INPUT, Context, DetectorConfig
from flowx_border.types import Finding

# Named credential formats. Each is anchored on a vendor prefix, which is what makes a
# match evidence rather than a guess. Ordered longest-prefix-first where two could
# overlap, so that `sk-ant-api03-` is not reported as the more generic `sk-`.
#
# Deliberately absent:
#   - Stripe `pk_live_`, which is a publishable key. It is designed to sit in client
#     side code, so blocking a request for containing one would be wrong.
#   - A bare 40 character base64 string for an AWS secret access key. Every sha1 in
#     every git log would match it. The entropy rule picks it up when a keyword is
#     nearby, which is the only context where the guess is worth making.
_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    (
        "slack_webhook",
        re.compile(r"https://hooks\.slack\.com/services/T[\w]+/B[\w]+/[\w]+"),
    ),
    ("slack_token", re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    (
        "anthropic_api_key",
        re.compile(r"\bsk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_-]{20,}"),
    ),
    ("openai_api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}")),
    ("stripe_secret_key", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{20,}\b")),
    ("private_key", re.compile(r"-----BEGIN\s[A-Z0-9 ]*PRIVATE KEY-----")),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ),
    (
        "basic_auth_url",
        re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s:/@]{6,}@[^\s/]+"),
    ),
)

# Words that mean "a credential follows". Multilingual because the input side is user
# text in 26 languages, and a Romanian user writes `parola` where an English one writes
# `password`. Without these the entropy rule cannot fire at all on the shapes that need
# context, so an English-only list would be an English-only detector.
_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        # English, and the machine-readable spellings that appear in config and headers.
        "key",
        "apikey",
        "api_key",
        "secret",
        "token",
        "password",
        "passwd",
        "pwd",
        "bearer",
        "authorization",
        "auth",
        "credential",
        "credentials",
        "privatekey",
        "private_key",
        "access_key",
        "secret_key",
        "client_secret",
        "passphrase",
        # The 26 languages the library claims. One or two words each: the common noun
        # for password, and for key where it differs usefully.
        "parola",
        "parolă",
        "parole",  # ro, it
        "hasło",
        "haslo",  # pl
        "jelszó",
        "jelszo",  # hu
        "şifre",
        "sifre",
        "anahtar",  # tr
        "şifrə",
        # "sifre" is the ASCII fallback for both tr and az; listed once above.
        "açar",  # az
        "contraseña",
        "contrasena",
        "clave",  # es
        "senha",
        "chave",  # pt
        "mot_de_passe",
        "motdepasse",
        "clé",  # fr
        "passwort",
        "kennwort",
        "schlüssel",  # de
        "wachtwoord",
        "sleutel",  # nl
        "adgangskode",
        "kodeord",
        "nøgle",  # da
        "lösenord",
        "nyckel",  # sv
        "salasana",
        "avain",  # fi
        "heslo",
        "klíč",
        "kluc",  # cs, sk
        "geslo",
        "ključ",  # sl
        "lozinka",
        "zaporka",  # hr
        "parool",
        "võti",  # et
        # "parole" is Latvian too, and is listed once under ro above.
        "atslēga",  # lv
        "slaptažodis",
        "raktas",  # lt
        "κωδικός",
        "κλειδί",  # el
        "парола",
        "ключ",  # bg
        "focal",
        "eochair",  # ga
        "passwerd",
        "ċavetta",  # mt
    }
)

# Casefolded, because the comparison below is against casefolded text and casefolding is
# not always identity-preserving on a literal. Greek is the case that caught this:
# "κωδικός".casefold() ends in σ rather than the final sigma ς, so the literal
# above can never match casefolded input. Folded once here rather than at every
# comparison.
_KEYWORDS_FOLDED: Final[frozenset[str]] = frozenset(
    word.casefold() for word in _KEYWORDS
)

# How far back to look for one of the above. 48 characters covers `AWS_SECRET_ACCESS_KEY
# = ` and a JSON key with whitespace, without reaching into the previous sentence.
_KEYWORD_WINDOW: Final = 48

# Candidate tokens for the entropy rule: runs of the characters credentials are made of.
# Splitting on everything else is what makes this one linear pass.
_TOKEN: Final = re.compile(r"[A-Za-z0-9+/=_\-\.]{16,}")

# Shapes that are high entropy and are not credentials. Each one is here because it
# occurs in ordinary text that a user would send to an assistant.
_NOT_A_SECRET: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    # A UUID. Request ids, correlation ids, and primary keys all look like this, and a
    # support question quoting one must not be a blocked request.
    (
        "uuid",
        re.compile(
            r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
            r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
        ),
    ),
    # A git object id or a content hash. Hexadecimal, and a hash is not a credential.
    ("hex_digest", re.compile(r"^[0-9a-f]{32,64}$|^[0-9A-F]{32,64}$")),
    # A version, a timestamp, or an ip-like dotted number.
    ("numeric", re.compile(r"^[0-9][0-9._\-]*$")),
    # A dotted path or a hostname: `com.example.service.internal`.
    ("dotted_name", re.compile(r"^[A-Za-z][A-Za-z0-9_-]*(\.[A-Za-z][A-Za-z0-9_-]*)+$")),
    # A file path fragment, which reaches the length threshold easily.
    ("path", re.compile(r"^[A-Za-z0-9_\-./]*/[A-Za-z0-9_\-./]*$")),
    # A credential that is public by design. Stripe publishable keys are meant to sit in
    # client-side code, so a request carrying one is not a leak, and blocking it
    # would be a refusal the user cannot work around. The secret counterparts
    # (sk_, rk_) are a named pattern above and are not excused here.
    ("publishable_key", re.compile(r"^pk_(?:live|test)_[0-9a-zA-Z]+$")),
)

# Length and entropy floors for the two entropy paths. The with-keyword path is looser
# because the keyword is itself evidence; the bare path has to stand alone.
_MIN_LENGTH_WITH_KEYWORD: Final = 16
_MIN_LENGTH_BARE: Final = 28
_MIN_ENTROPY_WITH_KEYWORD: Final = 3.0
_MIN_ENTROPY_BARE: Final = 4.0

# Base64 is the densest encoding these tokens use, so 6 bits per character is the
# ceiling a score is expressed against.
_MAX_BITS_PER_CHAR: Final = 6.0


def shannon_entropy(text: str) -> float:
    """Bits per character of the observed distribution.

    Per character rather than total, so that the threshold means the same thing for a 20
    character token and an 80 character one. A random base64 string approaches 6,
    English prose sits near 4 over a document but well under 3 for a single word.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _has_keyword_before(text: str, start: int) -> bool:
    """Whether a credential-ish word appears just before this token."""
    window = text[max(0, start - _KEYWORD_WINDOW) : start].casefold()
    # Split on anything that is not a word character, so that `API_KEY="` yields both
    # `api_key` and, via the second split, `api` and `key`. \w is Unicode aware, so
    # Greek, Cyrillic and the Latin diacritics all survive it.
    words = set(re.split(r"[^\w]+", window))
    words |= set(re.split(r"[^a-z0-9\u00c0-\uffff]+", window))
    return bool(words & _KEYWORDS_FOLDED)


def _mixed_classes(token: str) -> bool:
    """Whether the token draws on enough character classes to look generated.

    A long lowercase word is high enough entropy to pass the bare floor in some
    languages, and it is never a credential. Requiring three classes is what separates
    `Almindeligvis` from `k3Jf9dQ2xLm0`.
    """
    classes = sum(
        (
            any(c.islower() for c in token),
            any(c.isupper() for c in token),
            any(c.isdigit() for c in token),
            any(not c.isalnum() for c in token),
        )
    )
    return classes >= 3


def _segments_are_homogeneous(token: str) -> bool:
    """Whether the token is separator-joined runs of one character class each.

    This is what separates a human compound identifier from a generated string, and it
    catches a false positive the character-class test alone lets through:

        Ionescu-Bogdan-CNP-1920304050607   every segment is all letters or all digits
        2026-08-10-invoice-final-v2        same
        Zk3Jf9dQ2xLm0PqR7sT4uV6wX8yA1bC2  digits and letters interleave inside a segment

    Generated credentials interleave classes within a run because they come from one
    alphabet. Names, dates and reference numbers keep each run pure and separate
    them. So a token whose every segment is homogeneous is not treated as random.

    Applied only where no keyword is nearby. `password: abcdefgh-12345678` still
    fires: there the keyword is the evidence and this heuristic is not needed.
    """
    segments = [part for part in re.split(r"[-_.]", token) if part]
    if len(segments) < 2:
        return False
    return all(segment.isalpha() or segment.isdigit() for segment in segments)


class SecretsDetector:
    """Named credential patterns, then a conservative entropy rule."""

    id = "secrets"
    tier = "T0"
    sides = frozenset({INPUT})

    def warm(self) -> None:
        """Nothing to load. Patterns are compiled at import, so this is a no-op.

        It exists because the protocol requires it, and because a caller warming every
        detector should not have to know which ones have weights.
        """

    def run(
        self,
        text: str,
        cfg: DetectorConfig,
        ctx: Context,  # noqa: ARG002 - the Detector protocol fixes this signature
    ) -> list[Finding]:
        findings = self._pattern_findings(text, cfg)

        # Spans already claimed by a named pattern. The entropy rule skips them, because
        # `AKIA...` reported twice, once as an AWS key and once as a random string, is
        # one credential and two findings, and the second one tells the caller nothing.
        claimed = [(f.span[0], f.span[1]) for f in findings if f.span is not None]
        findings.extend(self._entropy_findings(text, cfg, claimed))
        return findings

    def _pattern_findings(self, text: str, cfg: DetectorConfig) -> list[Finding]:
        out: list[Finding] = []
        covered: list[tuple[int, int]] = []
        for label, pattern in _PATTERNS:
            for match in pattern.finditer(text):
                start, end = match.span()
                # A later, more generic pattern must not re-report a prefix of a match
                # already made: `sk-ant-api03-...` is not also an `openai_api_key`.
                if any(start >= s and end <= e for s, e in covered):
                    continue
                covered.append((start, end))
                out.append(
                    Finding(
                        detector_id=self.id,
                        tier=self.tier,
                        label=label,
                        # 1.0, and not a tuned number. A vendor prefix plus the right
                        # length and alphabet is not a probabilistic judgement.
                        score=1.0,
                        span=(start, end),
                        action=cfg.on_fail,
                    )
                )
        return out

    def _entropy_findings(
        self, text: str, cfg: DetectorConfig, claimed: list[tuple[int, int]]
    ) -> list[Finding]:
        """The rule that would produce the false positives, held back four ways.

        1. Known non-credential shapes are excluded outright: UUIDs, hex digests,
           dotted names, paths, plain numbers, publishable keys.
        2. Without a nearby keyword the token must be longer and more random, and must
           mix character classes, so an ordinary long word cannot trigger it.
        3. Without a nearby keyword a separator-joined token whose every segment is one
           character class is excluded: that is a name, a date or a reference number,
           not a generated string. See `_segments_are_homogeneous`.
        4. Anything a named pattern already reported is skipped.
        5. The score is the normalised entropy rather than 1.0, so a policy can set a
           threshold that keeps the block action for the certain cases and leaves this
           rule reporting.
        """
        out: list[Finding] = []
        for match in _TOKEN.finditer(text):
            token = match.group()
            start, end = match.span()
            if any(start >= s and end <= e for s, e in claimed):
                continue
            if any(pattern.match(token) for _, pattern in _NOT_A_SECRET):
                continue

            entropy = shannon_entropy(token)
            keyword = _has_keyword_before(text, start)
            if keyword:
                if (
                    len(token) < _MIN_LENGTH_WITH_KEYWORD
                    or entropy < _MIN_ENTROPY_WITH_KEYWORD
                ):
                    continue
            elif (
                len(token) < _MIN_LENGTH_BARE
                or entropy < _MIN_ENTROPY_BARE
                or not _mixed_classes(token)
                or _segments_are_homogeneous(token)
            ):
                continue

            score = min(1.0, entropy / _MAX_BITS_PER_CHAR)
            if score < cfg.threshold:
                continue
            out.append(
                Finding(
                    detector_id=self.id,
                    tier=self.tier,
                    # Two labels rather than one, because "we found a random string next
                    # to the word password" and "we found a random string" are different
                    # claims and an auditor should be able to tell them apart.
                    label="high_entropy_string_near_keyword"
                    if keyword
                    else "high_entropy_string",
                    score=score,
                    span=(start, end),
                    action=cfg.on_fail,
                )
            )
        return out
