# SPDX-License-Identifier: Apache-2.0
"""The load-bearing structures.

Decision is what a caller gets back. EvidenceRecord is what an auditor reads. The
difference matters: a Decision carries the text, an EvidenceRecord never does.

Every string field on an EvidenceRecord is pattern constrained. That is not defensive
style for its own sake, it is the mechanism that makes "no raw user text in a record"
an assertion a test can make about the type rather than about one example string. See
tests/test_types.py.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Annotated, Any, ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Verdict = Literal["allow", "redact", "block", "flag"]
Action = Literal["block", "redact", "rewrite", "flag", "log"]
Tier = Literal["T0", "T1", "T2", "T3"]
Direction = Literal["input", "output"]

# Version 7 UUID, RFC 4122 variant. The version nibble is pinned so a v4 cannot be
# passed off as a v7, because the record ordering guarantee depends on it.
_UUID7 = r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
_RFC3339_UTC = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$"
_SHA256 = r"^[0-9a-f]{64}$"
_COMMIT_SHA = r"^[0-9a-f]{40}$"
_IDENTIFIER = r"^[a-z][a-z0-9_]{0,63}$"
_POLICY_ID = r"^[a-z0-9][a-z0-9._-]{0,63}$"
_MODEL_ID = r"^[a-z0-9][a-z0-9._/-]{0,127}$"
_VERSION = r"^[0-9]+\.[0-9]+\.[0-9]+[0-9a-z.+-]*$"
# Ed25519 signature, 64 bytes, standard base64 with padding.
_ED25519_B64 = r"^[A-Za-z0-9+/]{86}==$"

RecordId = Annotated[str, Field(pattern=_UUID7)]
Timestamp = Annotated[str, Field(pattern=_RFC3339_UTC)]
Sha256 = Annotated[str, Field(pattern=_SHA256)]
CommitSha = Annotated[str, Field(pattern=_COMMIT_SHA)]
DetectorId = Annotated[str, Field(pattern=_IDENTIFIER)]
Label = Annotated[str, Field(pattern=_IDENTIFIER)]
PolicyId = Annotated[str, Field(pattern=_POLICY_ID)]
ModelId = Annotated[str, Field(pattern=_MODEL_ID)]
LibraryVersion = Annotated[str, Field(pattern=_VERSION)]
Signature = Annotated[str, Field(pattern=_ED25519_B64)]
Score = Annotated[float, Field(ge=0.0, le=1.0)]

# Scores are rounded before they reach a record. Python's float repr is stable across
# machines, but a verifier written in another language may not agree on the last bits
# of a 64 bit float, and a signature that only verifies in Python is not evidence.
SCORE_DECIMALS = 6


class _Strict(BaseModel):
    """Shared configuration.

    extra="forbid" is part of the no-raw-text guarantee: without it a caller could
    attach an undeclared field to a record and it would be signed along with
    everything else. protected_namespaces is cleared because model_id and
    model_revision are the documented field names and pydantic reserves model_ by
    default.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        protected_namespaces=(),
        validate_assignment=True,
    )


class Finding(_Strict):
    """One thing a detector found. Carries offsets, never the matched text."""

    detector_id: DetectorId
    tier: Tier
    label: Label
    score: Score
    span: tuple[int, int] | None = None
    action: Action
    model_id: ModelId | None = None
    model_revision: CommitSha | None = None

    @field_validator("span")
    @classmethod
    def _span_is_a_valid_slice(
        cls, span: tuple[int, int] | None
    ) -> tuple[int, int] | None:
        if span is None:
            return None
        start, end = span
        if start < 0 or end < 0:
            raise ValueError("span offsets must be non-negative")
        if start > end:
            raise ValueError("span start must not be after span end")
        return span


class FindingSummary(_Strict):
    """The redacted form of a Finding that goes into a record.

    CLAUDE.md specifies finding_summary as a list of dicts with detector_id, label,
    score and action. It is typed rather than left as a free dict so that the
    no-raw-text invariant is checkable. The serialised JSON is a list of objects with
    exactly those four keys, which is what the specified shape describes.
    """

    detector_id: DetectorId
    label: Label
    score: Score
    action: Action

    @field_validator("score")
    @classmethod
    def _quantise(cls, score: float) -> float:
        return round(score, SCORE_DECIMALS)


class DetectorAttestation(_Strict):
    """What ran, and which weights it ran with.

    The three model fields are None for a rule-based detector. That is the honest
    answer for secrets and disclosure, which have no weights to attest to.
    """

    id: DetectorId
    model_id: ModelId | None = None
    revision: CommitSha | None = None
    weights_sha256: Sha256 | None = None


class EvidenceRecord(_Strict):
    """The audit artifact.

    Contains hashes, never text. Serialise it with canonical_json so that the hash
    and the signature are reproducible on another machine.
    """

    record_id: RecordId
    timestamp: Timestamp
    direction: Direction
    policy_id: PolicyId
    policy_hash: Sha256
    library_version: LibraryVersion
    detectors: tuple[DetectorAttestation, ...]
    input_hash: Sha256
    verdict: Verdict
    finding_summary: tuple[FindingSummary, ...]
    signature: Signature | None = None


class Decision(_Strict):
    """What a caller gets back.

    text is the possibly redacted or rewritten form, original_text is what came in.
    Both are raw text, which is why a Decision is not the thing you archive.
    """

    verdict: Verdict
    text: str
    original_text: str
    findings: list[Finding]
    evidence: EvidenceRecord
    elapsed_ms: float = Field(ge=0.0)
    tiers_run: list[Tier]

    @model_validator(mode="after")
    def _tiers_run_has_no_duplicates(self) -> Decision:
        if len(set(self.tiers_run)) != len(self.tiers_run):
            raise ValueError("tiers_run must not repeat a tier")
        return self


def canonical_json(value: BaseModel | Mapping[str, Any] | Sequence[Any]) -> bytes:
    """Serialise to canonical JSON: sorted keys, no whitespace, UTF-8 bytes.

    Non-ASCII is emitted as itself rather than escaped, so a record for Romanian text
    hashes over the content and not over the serialiser's escaping choices. NaN and
    Infinity raise, because neither is JSON and a signature over either would not
    verify anywhere else.
    """
    payload: Any = (
        value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    )
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
