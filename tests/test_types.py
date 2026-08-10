# SPDX-License-Identifier: Apache-2.0
"""Tests for the core types.

Two invariants are load-bearing here and both are asserted structurally rather than
by example, because an example test only proves the one string it tried.

1. An EvidenceRecord has no field capable of holding raw user text.
2. canonical_json is byte-identical for equivalent objects.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from flowx_border.types import (
    Decision,
    DetectorAttestation,
    EvidenceRecord,
    Finding,
    FindingSummary,
    canonical_json,
)

# A string that could only have come from user text. If this ever turns up inside a
# serialised record, the record leaked.
MARKER = "Ana are mere and her IBAN is RO49AAAA1B31007593840000"

VALID_RECORD: dict[str, Any] = {
    "record_id": "018f4b7c-9c2a-7d3e-8f01-2a3b4c5d6e7f",
    "timestamp": "2026-08-10T09:41:02.123Z",
    "direction": "input",
    "policy_id": "bfsi-default",
    "policy_hash": "a" * 64,
    "library_version": "0.1.0",
    "detectors": [{"id": "secrets"}],
    "input_hash": "b" * 64,
    "verdict": "block",
    "finding_summary": [
        {
            "detector_id": "secrets",
            "label": "aws_access_key_id",
            "score": 1.0,
            "action": "block",
        }
    ],
    "signature": None,
}

# Every string-typed field on EvidenceRecord, including the nested attestation.
RECORD_STRING_FIELDS = [
    "record_id",
    "timestamp",
    "direction",
    "policy_id",
    "policy_hash",
    "library_version",
    "input_hash",
    "verdict",
    "signature",
]


def make_record(**overrides: Any) -> EvidenceRecord:
    return EvidenceRecord(**{**VALID_RECORD, **overrides})


# --------------------------------------------------------------------------------------
# Invariant 1: no field on an EvidenceRecord can hold raw text.
# --------------------------------------------------------------------------------------

# A string leaf is acceptable only if the schema constrains its shape. An
# unconstrained string is a place raw text can hide.
_CONSTRAINT_KEYS = ("pattern", "enum", "const")


def _resolve(node: dict[str, Any], defs: dict[str, Any]) -> dict[str, Any]:
    hops = 0
    while "$ref" in node:
        node = defs[node["$ref"].rsplit("/", maxsplit=1)[-1]]
        hops += 1
        if hops > 32:
            raise AssertionError("reference cycle in schema")
    return node


def assert_cannot_hold_text(
    node: dict[str, Any], defs: dict[str, Any], path: str
) -> None:
    """Walk a JSON schema and fail on anything that could carry arbitrary text."""
    node = _resolve(node, defs)

    for combinator in ("anyOf", "oneOf", "allOf"):
        if combinator in node:
            for index, branch in enumerate(node[combinator]):
                assert_cannot_hold_text(branch, defs, f"{path}.{combinator}[{index}]")
            return

    kind = node.get("type")

    if kind == "string":
        assert any(key in node for key in _CONSTRAINT_KEYS), (
            f"{path} is an unconstrained string, so it can hold raw user text"
        )
        return

    if kind == "object":
        assert node.get("additionalProperties") is False, (
            f"{path} accepts extra keys, so raw text can be smuggled in"
        )
        for name, sub in node.get("properties", {}).items():
            assert_cannot_hold_text(sub, defs, f"{path}.{name}")
        return

    if kind == "array":
        if "prefixItems" in node:
            for index, sub in enumerate(node["prefixItems"]):
                assert_cannot_hold_text(sub, defs, f"{path}[{index}]")
            return
        items = node.get("items")
        assert items is not None, f"{path} is an array with no item schema"
        assert_cannot_hold_text(items, defs, f"{path}[]")
        return

    if kind in ("integer", "number", "boolean", "null"):
        return

    raise AssertionError(f"{path} has no concrete type, so it is unconstrained: {node}")


def test_evidence_record_has_no_field_capable_of_holding_raw_text() -> None:
    schema = EvidenceRecord.model_json_schema()
    assert_cannot_hold_text(schema, schema.get("$defs", {}), "EvidenceRecord")


def test_the_structural_check_is_not_vacuous() -> None:
    """A Decision does legitimately hold raw text, so the same walk must reject it.

    Without this, a bug in the walker would make the test above pass for free.
    """
    schema = Decision.model_json_schema()
    with pytest.raises(AssertionError, match="unconstrained string"):
        assert_cannot_hold_text(schema, schema.get("$defs", {}), "Decision")


@pytest.mark.parametrize("field", RECORD_STRING_FIELDS)
def test_marker_text_is_rejected_by_every_string_field(field: str) -> None:
    with pytest.raises(ValidationError):
        make_record(**{field: MARKER})


@pytest.mark.parametrize("field", ["id", "model_id", "revision", "weights_sha256"])
def test_marker_text_is_rejected_by_every_attestation_field(field: str) -> None:
    with pytest.raises(ValidationError):
        DetectorAttestation(**{"id": "pii", field: MARKER})


@pytest.mark.parametrize("field", ["detector_id", "label", "action"])
def test_marker_text_is_rejected_by_every_finding_summary_field(field: str) -> None:
    valid = {
        "detector_id": "pii",
        "label": "email",
        "score": 0.9,
        "action": "redact",
    }
    with pytest.raises(ValidationError):
        FindingSummary(**{**valid, field: MARKER})


def test_an_extra_field_cannot_be_added_to_a_record() -> None:
    with pytest.raises(ValidationError):
        make_record(user_text=MARKER)


def test_a_record_is_immutable_once_built() -> None:
    record = make_record()
    with pytest.raises(ValidationError):
        record.verdict = "allow"  # type: ignore[misc]


# --------------------------------------------------------------------------------------
# Invariant 2: canonical JSON is reproducible.
# --------------------------------------------------------------------------------------


def test_canonical_json_is_byte_identical_for_equivalent_records() -> None:
    first = make_record()
    reordered = EvidenceRecord(**dict(reversed(list(VALID_RECORD.items()))))
    assert canonical_json(first) == canonical_json(reordered)


def test_canonical_json_is_stable_across_repeated_calls() -> None:
    record = make_record()
    assert canonical_json(record) == canonical_json(record)


def test_canonical_json_sorts_keys_and_emits_no_whitespace() -> None:
    raw = canonical_json(make_record()).decode("utf-8")
    assert ", " not in raw
    assert ": " not in raw
    keys = list(json.loads(raw).keys())
    assert keys == sorted(keys)


def test_canonical_json_does_not_escape_non_ascii() -> None:
    # Escaping would make records for the non-English languages larger and would make
    # the bytes depend on the serialiser rather than on the content.
    assert (
        canonical_json({"town": "Târgu Mureș"})
        == b'{"town":"T\xc3\xa2rgu Mure\xc8\x99"}'
    )


def test_canonical_json_refuses_non_finite_numbers() -> None:
    # NaN and Infinity are not JSON, and a signature over them would not verify
    # anywhere else.
    with pytest.raises(ValueError, match="not JSON compliant"):
        canonical_json({"score": float("inf")})


def test_score_in_a_summary_is_quantised_so_the_hash_is_portable() -> None:
    summary = FindingSummary(
        detector_id="injection",
        label="prompt_injection",
        score=0.1234567891,
        action="block",
    )
    assert summary.score == 0.123457


# --------------------------------------------------------------------------------------
# Field validation
# --------------------------------------------------------------------------------------


def test_a_finding_span_must_be_ordered_and_non_negative() -> None:
    with pytest.raises(ValidationError):
        Finding(
            detector_id="pii",
            tier="T1",
            label="email",
            score=0.9,
            span=(9, 4),
            action="redact",
        )
    with pytest.raises(ValidationError):
        Finding(
            detector_id="pii",
            tier="T1",
            label="email",
            score=0.9,
            span=(-1, 4),
            action="redact",
        )


def test_a_score_outside_zero_to_one_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Finding(detector_id="pii", tier="T1", label="email", score=1.4, action="redact")


def test_a_model_revision_must_be_a_commit_sha_not_a_branch() -> None:
    # CLAUDE.md pins revisions to commit shas. "main" moving under us would break
    # both determinism and the attestation.
    with pytest.raises(ValidationError):
        DetectorAttestation(id="pii", model_id="gliner-multi", revision="main")
    ok = DetectorAttestation(id="pii", model_id="gliner-multi", revision="c" * 40)
    assert ok.revision == "c" * 40


def test_an_unknown_tier_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Finding(detector_id="pii", tier="T9", label="email", score=0.5, action="flag")


def test_a_rule_based_detector_attests_without_a_model() -> None:
    attestation = DetectorAttestation(id="secrets")
    assert attestation.model_id is None
    assert attestation.weights_sha256 is None
