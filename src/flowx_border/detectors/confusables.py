# SPDX-License-Identifier: Apache-2.0
"""T1: words that look like one thing and are spelled as another.

`banned_terms` matches `acme` and a Cyrillic `а` in front of `cme` walks past it,
because to a string comparison those are different words and to a reader they are the
same one.
`internal_domains` has the same hole with a lookalike hostname. This detector closes it
with the Unicode Consortium's own answer to the question, the UTS #39 confusable
skeleton, and it reports two things.

`lookalike_term`
    A run of text that folds onto a term the policy lists, without being that term. The
    comparison is the UTS #39 skeleton: `аcme` with a Cyrillic а, `ACME` spelled in
    Cyrillic capitals, `acrne` with r and n standing in for m, and `paypa1` all fold
    onto what they imitate. An exact match, in any case, is not reported: that is
    `banned_terms` doing its job, and reporting it twice would count one word as two
    findings. A term with dots is a hostname, so `login.аcme.com` matches `acme.com`.

`mixed_script`
    One word written in two scripts, where a letter from the minority script could pass
    for a letter of the majority one. `аcme` is Latin with one Cyrillic letter that
    renders as `a`. Needs no list, which is why this half is on in the shipped policy.

What the 26 languages ask of it
-------------------------------

Greek and Bulgarian are written in their own scripts, and a word in either is one
script, so neither half fires on them. Turkish and Azerbaijani use a dotless ı, schwa
and a dotted capital İ, all of them Latin letters, so a Turkish word is not mixed script
either. Maltese ħ, ġ, ż and the Irish fada are Latin letters with marks, and combining
marks belong to no script here.

**The one exemption is the dotless ı.** UTS #39 maps it onto i, which is right for a
hostname and wrong for Turkish, where `sık` (frequent) and `sik` are different words and
one of them is exactly the kind a term list carries. Without the exemption the common
word would be reported as a disguise of the rare one on every Turkish scan that used it.
The reverse attack, a dotless ı slipped into a Latin brand name, is given up for this;
see `EXEMPT`.

Mixed script needs a word boundary to mean anything, so a word is split on hyphens,
dots, digits and apostrophes before its scripts are counted. Bulgarian writes a suffix
onto a Latin loan with a hyphen (`PDF-а`, `SMS-ите`), and scientific prose writes
`β-каротин` and `α-helix`; each half of those is one script. Han, Hiragana and Katakana
together count as one, as UTS #39 counts them, so a Japanese name is not mixed script.

The data
--------

`data/confusables.json` is generated from two Unicode files by `build` below and records
the version, date and sha256 of each: `confusables.txt` from the UTS #39 security data,
and `Scripts.txt` from the UCD of the same version. Nothing is fetched at run time and
nothing outside the standard library is imported. To refresh it:

    python -m flowx_border.detectors.confusables build confusables.txt Scripts.txt

Options
-------

    terms:         list[str], default empty. The words and hostnames a lookalike of
                   which is worth reporting. Usually the same list `banned_terms` and
                   `internal_domains` carry; a YAML anchor shares one list among all
                   three.
    mixed_script:  bool, default true.

Enabled with no terms and `mixed_script: false` it has nothing to look for, and says so
with `terms_not_configured` at action `log` on every scan rather than returning a clean
result nobody earned.

Budget is 5 ms at p95 at the reference input: one pass building two skeleton keys from a
per-character cache, one pass over the words for script counts, and a string search per
term.
"""

from __future__ import annotations

import bisect
import functools
import hashlib
import json
import re
import sys
import unicodedata
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Final

from flowx_border.detectors.base import INPUT, OUTPUT, Context, DetectorConfig
from flowx_border.types import Finding

_DATA: Final = Path(__file__).resolve().parent.parent / "data" / "confusables.json"

#: Code points whose UTS #39 mapping is deliberately not applied, and why. Each one is a
#: letter of a supported language that the standard folds onto a different letter of
#: the same script, which in that language is a different word rather than a disguise.
EXEMPT: Final[dict[str, str]] = {
    "ı": "Turkish and Azerbaijani dotless i, a letter distinct from i in both",
}

#: Scripts UTS #39 treats as one writing system when they appear together.
_SCRIPT_GROUPS: Final[dict[str, str]] = {
    "Hiragana": "Han",
    "Katakana": "Han",
    "Bopomofo": "Han",
    "Hangul": "Han",
}

_LABEL_TERM: Final = "lookalike_term"
_LABEL_MIXED: Final = "mixed_script"


class ConfusablesError(ValueError):
    """The detector is enabled with options it cannot act on."""


class _Tables:
    """The generated data, loaded once. Kept off the import path on purpose."""

    def __init__(self, raw: dict[str, object]) -> None:
        mapping = raw["map"]
        names = raw["script_names"]
        ranges = raw["script_ranges"]
        if not (
            isinstance(mapping, dict)
            and isinstance(names, list)
            and isinstance(ranges, list)
        ):
            raise ConfusablesError(
                f"{_DATA} is not the shape `build` writes. Regenerate it rather than "
                "editing it by hand."
            )
        self.map: dict[str, str] = {
            str(k): str(v) for k, v in mapping.items() if k not in EXEMPT
        }
        self.names: list[str] = [str(n) for n in names]
        self.starts: list[int] = [int(r[0]) for r in ranges]
        self.ends: list[int] = [int(r[1]) for r in ranges]
        self.index: list[int] = [int(r[2]) for r in ranges]
        self._prototypes: dict[str, frozenset[str]] = {}

    def script(self, char: str) -> str | None:
        """The script of `char`, or None for Common, Inherited and unassigned."""
        point = ord(char)
        at = bisect.bisect_right(self.starts, point) - 1
        if at < 0 or point > self.ends[at]:
            return None
        name = self.names[self.index[at]]
        return _SCRIPT_GROUPS.get(name, name)

    def skeleton(self, text: str) -> str:
        """UTS #39 skeleton: NFD, map each code point, NFD again."""
        decomposed = unicodedata.normalize("NFD", text)
        mapped = "".join(self.map.get(c, c) for c in decomposed)
        return unicodedata.normalize("NFD", mapped)

    def prototypes(self, script: str) -> frozenset[str]:
        """Every skeleton a single letter of `script` folds to."""
        found = self._prototypes.get(script)
        if found is None:
            out: set[str] = set()
            for at, index in enumerate(self.index):
                name = self.names[index]
                if _SCRIPT_GROUPS.get(name, name) != script:
                    continue
                for point in range(self.starts[at], self.ends[at] + 1):
                    char = chr(point)
                    if unicodedata.category(char).startswith("L"):
                        out.add(self.skeleton(char))
            found = frozenset(out)
            self._prototypes[script] = found
        return found


@functools.cache
def tables() -> _Tables:
    if not _DATA.exists():
        raise ConfusablesError(
            f"no confusables data at {_DATA}. This file ships inside the package; its "
            "absence means a broken install rather than a missing download."
        )
    return _Tables(json.loads(_DATA.read_text(encoding="utf-8")))


def _is_ignorable(char: str) -> bool:
    # Format characters: zero-width space and joiner, soft hyphen, bidi controls. They
    # render as nothing, so they must not break a word or change what it folds to.
    return unicodedata.category(char) == "Cf"


@functools.cache
def _char_keys(char: str) -> tuple[str, str]:
    """Two skeleton keys for one character: case kept first, and case folded first.

    Two because case and confusability interact. Cyrillic capitals `АСМЕ` are a perfect
    `ACME`, but folded first they become `асме`, whose м folds to a turned w rather than
    to m. Cyrillic `і` in `vіsa` is the other way round: its capital folds to l. A
    lookalike found under either key is a lookalike.
    """
    t = tables()
    case_kept = t.skeleton(t.skeleton(char).casefold())
    case_folded = t.skeleton(t.skeleton(char.casefold()).casefold())
    return case_kept, case_folded


def _keys(text: str) -> list[tuple[str, list[int]]]:
    """Both skeleton keys of `text`, each with the source index of every key character.

    Whitespace runs collapse to one space and format characters vanish, so the keys
    of `acme  bank` and `ac\u200bme bank` are the key of `acme bank`. The two keys
    are aligned separately because a character can expand in one and not the other.
    """
    kept: list[str] = []
    folded: list[str] = []
    kept_at: list[int] = []
    folded_at: list[int] = []
    spaced = False
    for index, char in enumerate(text):
        if char.isspace():
            if not spaced:
                kept.append(" ")
                folded.append(" ")
                kept_at.append(index)
                folded_at.append(index)
            spaced = True
            continue
        if _is_ignorable(char):
            continue
        spaced = False
        a, b = _char_keys(char)
        kept.append(a)
        folded.append(b)
        kept_at.extend([index] * len(a))
        folded_at.extend([index] * len(b))
    return [("".join(kept), kept_at), ("".join(folded), folded_at)]


def _plain(text: str) -> str:
    """What an exact match is compared under: NFC, case folded, no format characters."""
    visible = "".join(c for c in text if not _is_ignorable(c))
    return " ".join(unicodedata.normalize("NFC", visible).casefold().split())


@functools.cache
def _term_keys(term: str) -> frozenset[str]:
    return frozenset(key.strip() for key, _ in _keys(term.strip()) if key.strip())


def _bounded(key: str, start: int, end: int) -> bool:
    before = key[start - 1] if start > 0 else " "
    after = key[end] if end < len(key) else " "
    # A dot or hyphen before the match is a boundary: `login.аcme.com` ends in
    # `acme.com`, and German and Azerbaijani hang words off a name with a hyphen
    # (`Acme-Auszug`, `Acme-nin`). A dot after it is one only when it ends a sentence.
    return not (before.isalnum() or before == "_") and not (
        after.isalnum() or after == "_" or (after == "." and _continues(key, end))
    )


def _continues(key: str, dot: int) -> bool:
    """Whether the dot at `dot` is inside a hostname rather than ending a sentence."""
    return dot + 1 < len(key) and key[dot + 1].isalnum()


def lookalikes(text: str, terms: Sequence[str]) -> list[tuple[int, int]]:
    """Spans of `text` that fold onto one of `terms` without being it."""
    if not terms:
        return []
    keyed = _keys(text)
    found: set[tuple[int, int]] = set()
    for term in terms:
        plain_term = _plain(term)
        for needle in _term_keys(term):
            for key, origin in keyed:
                at = key.find(needle)
                while at != -1:
                    end = at + len(needle)
                    if _bounded(key, at, end):
                        span = (origin[at], origin[end - 1] + 1)
                        if _plain(text[span[0] : span[1]]) != plain_term:
                            found.add(span)
                    at = key.find(needle, at + 1)
    return sorted(found)


#: Splits a word into the parts whose scripts are counted separately. Letters, marks
#: and format characters continue a part; anything else ends it.
def _parts(text: str) -> Iterator[tuple[int, int]]:
    start = -1
    for index, char in enumerate(text):
        category = unicodedata.category(char)
        inside = category[0] in "LM" or category == "Cf"
        if inside and start < 0:
            start = index
        elif not inside and start >= 0:
            yield start, index
            start = -1
    if start >= 0:
        yield start, len(text)


def mixed_script(text: str) -> list[tuple[int, int]]:
    """Spans of words written in two scripts where one letter can pass for the other."""
    t = tables()
    found: list[tuple[int, int]] = []
    for start, end in _parts(text):
        part = text[start:end]
        if part.isascii():
            continue
        counts: dict[str, int] = {}
        letters: list[tuple[str, str]] = []
        for char in part:
            if not unicodedata.category(char).startswith("L"):
                continue
            script = t.script(char)
            if script is None:
                continue
            counts[script] = counts.get(script, 0) + 1
            letters.append((char, script))
        if len(counts) < 2:
            continue
        most = max(counts.values())
        for host in (s for s, n in counts.items() if n == most):
            native = t.prototypes(host)
            if any(s != host and t.skeleton(c) in native for c, s in letters):
                found.append((start, end))
                break
    return found


class ConfusablesDetector:
    """UTS #39 skeletons against a policy's terms, and mixed-script words."""

    id = "confusables"
    tier = "T1"
    sides = frozenset({INPUT, OUTPUT})

    def warm(self) -> None:
        """Load the generated tables and the Latin prototypes, the one every text uses.

        The other scripts' prototypes are built the first time a word needs them, which
        costs a few milliseconds once per process rather than on every scan.
        """
        tables().prototypes("Latin")

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
        if not isinstance(raw, list | tuple):
            raise ConfusablesError(
                f"confusables terms must be a list of strings, got {type(raw).__name__}"
            )
        terms = tuple(str(term) for term in raw if str(term).strip())
        check_mixed = options.get("mixed_script", True)
        if not isinstance(check_mixed, bool):
            raise ConfusablesError("confusables mixed_script must be true or false")

        if not terms and not check_mixed:
            return [
                Finding(
                    detector_id=self.id,
                    tier=self.tier,
                    label="terms_not_configured",
                    score=1.0,
                    span=None,
                    # Log, as in banned_terms: a gap in the policy is not a finding
                    # about the text.
                    action="log",
                )
            ]

        spans = [(span, _LABEL_TERM) for span in lookalikes(text, terms)]
        if check_mixed:
            spans += [(span, _LABEL_MIXED) for span in mixed_script(text)]
        return [
            Finding(
                detector_id=self.id,
                tier=self.tier,
                label=label,
                # 1.0: the skeleton either matches or it does not, and there is no
                # model here to be unsure.
                score=1.0,
                span=span,
                action=cfg.on_fail,
            )
            for span, label in sorted(spans)
        ]


# ------------------------------------------------------------------------ the builder


def _parse_header(text: str) -> dict[str, str]:
    header: dict[str, str] = {}
    for line in text.splitlines()[:12]:
        match = re.match(r"#\s*(Date|Version):\s*(.+)", line)
        if match:
            header[match.group(1).lower()] = match.group(2).strip()
        first = re.match(r"#\s*Scripts-(\d+\.\d+\.\d+)\.txt", line)
        if first:
            header["version"] = first.group(1)
    return header


def build(confusables_path: Path, scripts_path: Path) -> dict[str, object]:
    """Generate the data file from two Unicode sources, recording where each is from."""
    confusables_bytes = confusables_path.read_bytes()
    scripts_bytes = scripts_path.read_bytes()
    confusables_text = confusables_bytes.decode("utf-8-sig")
    scripts_text = scripts_bytes.decode("utf-8")

    mapping: dict[str, str] = {}
    for line in confusables_text.splitlines():
        body = line.split("#", 1)[0].strip()
        if not body:
            continue
        source, target, _kind = (field.strip() for field in body.split(";"))
        mapping[chr(int(source, 16))] = "".join(
            chr(int(point, 16)) for point in target.split()
        )

    names: list[str] = []
    ranges: list[list[int]] = []
    for line in scripts_text.splitlines():
        body = line.split("#", 1)[0].strip()
        if not body:
            continue
        points, name = (field.strip() for field in body.split(";"))
        if name in {"Common", "Inherited"}:
            continue
        low, _, high = points.partition("..")
        start, end = int(low, 16), int(high or low, 16)
        if name not in names:
            names.append(name)
        ranges.append([start, end, names.index(name)])
    ranges.sort()
    merged: list[list[int]] = []
    for start, end, index in ranges:
        if merged and merged[-1][2] == index and merged[-1][1] + 1 == start:
            merged[-1][1] = end
        else:
            merged.append([start, end, index])

    base = "https://www.unicode.org/Public"
    c_header = _parse_header(confusables_text)
    s_header = _parse_header(scripts_text)
    return {
        "built_by": "python -m flowx_border.detectors.confusables build",
        "confusables": {
            "source": f"{base}/{c_header.get('version', '?')}/security/confusables.txt",
            "version": c_header.get("version", "?"),
            "date": c_header.get("date", "?"),
            "sha256": hashlib.sha256(confusables_bytes).hexdigest(),
        },
        "scripts": {
            "source": f"{base}/{s_header.get('version', '?')}/ucd/Scripts.txt",
            "version": s_header.get("version", "?"),
            "date": s_header.get("date", "?"),
            "sha256": hashlib.sha256(scripts_bytes).hexdigest(),
        },
        "reading_this": (
            "map is confusables.txt, source code point to its prototype. "
            "script_ranges is Scripts.txt without Common and Inherited, merged, as "
            "[first, last, index into script_names]. Unicode data files are "
            "distributed under the Unicode License v3."
        ),
        "map": mapping,
        "script_names": names,
        "script_ranges": merged,
    }


def main(argv: Sequence[str]) -> int:
    if len(argv) != 3 or argv[0] != "build":
        print(
            "usage: python -m flowx_border.detectors.confusables build "
            "confusables.txt Scripts.txt",
            file=sys.stderr,
        )
        return 2
    data = build(Path(argv[1]), Path(argv[2]))
    _DATA.write_text(
        # Escaped, so the file is ASCII: the table maps dashes and quotes onto each
        # other, and a literal em-dash in the repository fails its style check.
        json.dumps(data, ensure_ascii=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
