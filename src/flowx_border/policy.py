# SPDX-License-Identifier: Apache-2.0
"""Policy: data, not code.

A policy is YAML. It has no Python callbacks and no expressions, because constraint 5
says a compliance officer who does not write Python must be able to read and review one.
That constraint is what makes the policy hash meaningful: the document fully determines
the behaviour, so hashing the document pins the behaviour.

Two things here earn their complexity.

**Unknown detector ids are an error.** A policy that says `pii_detector:` when it means
`pii:` would otherwise disable PII checking and report success. Silence is the worst
outcome available, so it raises.

**The hash is over the resolved document, not the file.** Two policies that mean the
same thing must hash the same even if one omits a default the other states, and
reformatting or reordering YAML must not change the hash. So defaults are filled in
first, then the result is serialised as canonical JSON and hashed. `policy_hash` is what
lands in the evidence record, and an auditor comparing two records is comparing meaning
rather than whitespace.
"""

from __future__ import annotations

import hashlib
from os import PathLike
from pathlib import Path
from typing import Any, ClassVar, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from flowx_border.detectors.base import DetectorConfig
from flowx_border.detectors.catalogue import ALWAYS_ON, CATALOGUE, TIER_ORDER
from flowx_border.types import Action, Tier, canonical_json

FailMode = Literal["open", "closed"]

DEFAULT_FAIL_MODE: FailMode = "open"

# The only keys a policy file may set. `hash` is deliberately absent: it is computed
# over the resolved document, and a policy that could declare it could lie about it.
_TOP_LEVEL_KEYS: frozenset[str] = frozenset(
    {"policy_id", "version", "description", "fail_mode", "detectors"}
)


class PolicyError(ValueError):
    """A policy that cannot be used. Raised rather than warned about, deliberately."""


class DetectorPolicy(BaseModel):
    """What a policy says about one detector."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = True
    threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    on_fail: Action = "flag"
    # T3 only: run even when no lower tier flagged. Meaningless elsewhere, and the
    # validator below rejects it elsewhere rather than ignoring it.
    always: bool = False
    options: dict[str, Any] = Field(default_factory=dict)

    def to_detector_config(self) -> DetectorConfig:
        return DetectorConfig(
            enabled=self.enabled,
            threshold=self.threshold,
            on_fail=self.on_fail,
            always=self.always,
            options=dict(self.options),
        )


class Policy(BaseModel):
    """A resolved, validated policy.

    `hash` is computed at load time over the canonical JSON of this document. It is not
    a field a policy file can set: a policy that could declare its own hash could lie
    about it.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    policy_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    version: int = Field(ge=1)
    description: str = ""
    fail_mode: dict[Tier, FailMode]
    detectors: dict[str, DetectorPolicy]

    @model_validator(mode="after")
    def _check(self) -> Policy:
        unknown = sorted(set(self.detectors) - set(CATALOGUE))
        if unknown:
            close = {u: _nearest(u) for u in unknown}
            hint = ", ".join(
                f"{u!r}" + (f" (did you mean {close[u]!r}?)" if close[u] else "")
                for u in unknown
            )
            raise PolicyError(
                f"unknown detector id(s): {hint}. A misspelled id would silently "
                f"disable a check, so it is rejected. Known ids: "
                f"{', '.join(sorted(CATALOGUE))}"
            )

        missing_tiers = [tier for tier in TIER_ORDER if tier not in self.fail_mode]
        if missing_tiers:
            raise PolicyError(
                f"fail_mode is missing tier(s): {', '.join(missing_tiers)}"
            )

        for detector, entry in self.detectors.items():
            spec = CATALOGUE[detector]
            if detector in ALWAYS_ON and not entry.enabled:
                raise PolicyError(
                    f"{detector} is {spec.tier} and cannot be disabled. T0 always "
                    "runs: it is the floor, and a policy that could switch it off "
                    "would make the floor optional."
                )
            if entry.always and spec.tier != "T3":
                raise PolicyError(
                    f"{detector} is {spec.tier}, so 'always' means nothing for it. "
                    "'always' only applies to T3, which otherwise runs solely on "
                    "escalation. Remove it rather than leaving it misleading."
                )
        return self

    def for_detector(self, detector: str) -> DetectorPolicy:
        """The policy for one detector, defaulted if the file did not mention it."""
        return self.detectors.get(detector, DetectorPolicy())

    def enabled_for(self, detector: str) -> bool:
        return detector in ALWAYS_ON or self.for_detector(detector).enabled

    @property
    def hash(self) -> str:
        return hashlib.sha256(canonical_json(self)).hexdigest()


def _nearest(name: str) -> str | None:
    """Cheapest useful typo hint: a known id that shares a prefix or is contained."""
    for known in sorted(CATALOGUE):
        if known in name or name in known:
            return known
    return None


def _resolve(raw: dict[str, Any]) -> dict[str, Any]:
    """Fill in defaults so that two policies meaning the same thing hash the same.

    This is the step that makes the hash meaningful. Without it, omitting `threshold:
    0.5` would produce a different hash from stating it, and an auditor comparing two
    records could not tell "different policy" from "differently formatted policy".
    """
    if not isinstance(raw, dict):
        raise PolicyError("a policy document must be a mapping at the top level")

    # Unknown top-level keys are rejected for the same reason unknown detector ids are:
    # `fail_modes` mistyped in the plural would otherwise be dropped here, the policy
    # would default to open, and nothing would say so. extra="forbid" on the model
    # cannot catch it, because this function builds its output from known keys and never
    # passes the stray one through.
    unknown_keys = sorted(set(raw) - _TOP_LEVEL_KEYS)
    if unknown_keys:
        raise PolicyError(
            "unknown top-level key(s) in policy: "
            f"{', '.join(repr(k) for k in unknown_keys)}. Allowed: "
            f"{', '.join(sorted(_TOP_LEVEL_KEYS))}. A dropped key would change "
            "behaviour silently, so it is rejected. Note 'hash' is computed, not "
            "declared: a policy that could state its own hash could lie about it."
        )

    resolved: dict[str, Any] = {
        "policy_id": raw.get("policy_id"),
        "version": raw.get("version", 1),
        "description": raw.get("description", ""),
    }

    declared = raw.get("fail_mode") or {}
    if isinstance(declared, str):
        # A single value applies to every tier. Convenience, but it is expanded here so
        # the resolved document is always explicit and always hashes the same.
        declared = dict.fromkeys(TIER_ORDER, declared)
    if not isinstance(declared, dict):
        raise PolicyError(
            "fail_mode must be a mapping of tier to open|closed, or a single value"
        )
    resolved["fail_mode"] = {
        tier: declared.get(tier, DEFAULT_FAIL_MODE) for tier in TIER_ORDER
    }

    detectors = raw.get("detectors") or {}
    if not isinstance(detectors, dict):
        raise PolicyError("detectors must be a mapping of detector id to settings")

    # Every known detector appears in the resolved document, defaulted if absent. That
    # way the hash covers the whole decision surface: adding a detector to the catalogue
    # changes every policy's hash, which is correct, because it changes what runs.
    out: dict[str, Any] = {}
    for detector in sorted(CATALOGUE):
        entry = detectors.get(detector)
        if entry is None:
            entry = {}
        elif entry is True:
            entry = {"enabled": True}
        elif entry is False:
            entry = {"enabled": False}
        elif not isinstance(entry, dict):
            raise PolicyError(
                f"detectors.{detector} must be a mapping, true, or false, not "
                f"{type(entry).__name__}"
            )
        out[detector] = entry

    # Ids the file mentioned that are not in the catalogue are preserved so the model
    # validator can name them in the error, rather than being dropped here.
    for detector, entry in detectors.items():
        if detector not in CATALOGUE:
            out[detector] = entry if isinstance(entry, dict) else {}

    resolved["detectors"] = out
    return resolved


def load_policy(path: str | PathLike[str]) -> Policy:
    """Load, validate and resolve a policy, and compute its hash.

    Raises PolicyError for anything wrong with the document. It does not fall back to a
    default policy: a scan running under a policy the caller did not write is worse than
    a scan that refuses to start.
    """
    source = Path(path)
    if not source.exists():
        raise PolicyError(f"no policy file at {source}")

    try:
        raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        raise PolicyError(f"{source} is not valid YAML: {error}") from error

    if raw is None:
        raise PolicyError(f"{source} is empty")

    resolved = _resolve(raw)
    if resolved["policy_id"] is None:
        raise PolicyError(f"{source} has no policy_id")

    try:
        return Policy.model_validate(resolved)
    except PolicyError:
        raise
    except ValidationError as error:
        raise PolicyError(f"{source} is not a valid policy: {error}") from error
