# SPDX-License-Identifier: Apache-2.0
"""Tests for the json_schema detector.

Ports `valid_open_api_spec`, and the first test is that it still does the original's job
when pointed at the original's schema. The rest is the generalisation: the schema is the
caller's, it lives in the policy, and a schema that is itself broken is an error rather
than a wall of findings about the model.
"""

from __future__ import annotations

import pytest

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.json_schema import (
    JsonSchemaDetector,
    JsonSchemaError,
    is_available,
)
from flowx_border.types import Finding

pytestmark = pytest.mark.skipif(
    not is_available(),
    reason="jsonschema not installed; json_schema is outside CORE, install the extra",
)

DETECTOR = JsonSchemaDetector()
CTX = Context()

ORDER = {
    "type": "object",
    "required": ["id", "total"],
    "properties": {
        "id": {"type": "string"},
        "total": {"type": "number", "minimum": 0},
    },
}


def run(text: str, **options: object) -> list[Finding]:
    return DETECTOR.run(text, DetectorConfig(on_fail="flag", options=options), CTX)


def labels(text: str, **options: object) -> list[str]:
    return [finding.label for finding in run(text, **options)]


# ------------------------------------------------------- the unconfigured case first


def test_no_schema_reports_that_rather_than_a_clean_scan() -> None:
    found = run('{"anything": true}')
    assert [f.label for f in found] == ["schema_not_configured"]
    assert found[0].action == "log"


def test_the_unconfigured_finding_never_blocks() -> None:
    found = DETECTOR.run("{}", DetectorConfig(on_fail="block"), CTX)
    assert found[0].action == "log"


# ------------------------------------------------------------------ what it reports


def test_output_matching_the_schema_is_clean() -> None:
    assert run('{"id": "A1", "total": 42}', schema=ORDER) == []


def test_output_violating_the_schema_is_reported() -> None:
    assert labels('{"id": "A1"}', schema=ORDER) == ["schema_violation"]
    assert labels('{"id": 7, "total": 42}', schema=ORDER) == ["schema_violation"]
    assert labels('{"id": "A1", "total": -1}', schema=ORDER) == ["schema_violation"]


def test_output_that_is_not_json_is_a_different_finding() -> None:
    # Not parsing and not conforming are different problems with different fixes.
    assert labels("I could not produce that.", schema=ORDER) == ["not_json"]


def test_an_empty_output_is_not_invalid_json() -> None:
    # It is no JSON. Reporting `not_json` would fire on every answer a policy applied
    # this to by mistake.
    assert run("", schema=ORDER) == []
    assert run("   ", schema=ORDER) == []


def test_a_broken_schema_raises_rather_than_failing_every_output() -> None:
    """Otherwise the caller reads a wall of findings and looks in the wrong place.

    A schema with a type that does not exist rejects everything, and the symptom is
    indistinguishable from a model that has stopped producing valid output.
    """
    with pytest.raises(JsonSchemaError, match="not a valid JSON Schema"):
        run('{"a": 1}', schema={"type": "objekt"})


def test_a_schema_that_is_not_a_mapping_raises() -> None:
    with pytest.raises(JsonSchemaError, match="must be a mapping"):
        run('{"a": 1}', schema="/etc/schemas/order.json")


def test_the_schema_is_data_so_it_changes_the_policy_hash() -> None:
    """Which is the reason a path was rejected in favour of an inline schema.

    A path would let the behaviour of a scan change without the policy hash changing,
    and every evidence record citing that hash would claim to pin something it no
    longer pins.
    """
    from flowx_border.policy import DetectorPolicy, Policy

    def policy_with(schema: dict[str, object]) -> Policy:
        return Policy(
            policy_id="schema-test",
            version=1,
            fail_mode=dict.fromkeys(("T0", "T1", "T2", "T3"), "open"),
            detectors={"json_schema": DetectorPolicy(options={"schema": schema})},
        )

    assert policy_with(ORDER).hash != policy_with({"type": "array"}).hash


# ----------------------------------------------------- it still does the original job


def test_it_validates_an_openapi_document_when_pointed_at_that_schema() -> None:
    """`valid_open_api_spec` is this detector with one schema, which is the port.

    A cut-down meta-schema rather than the full OpenAPI one, because the point is that
    the caller supplies the schema, not that this library ships a copy of somebody
    else's and has to keep it current.
    """
    openapi = {
        "type": "object",
        "required": ["openapi", "info", "paths"],
        "properties": {
            "openapi": {"type": "string", "pattern": "^3\\."},
            "info": {
                "type": "object",
                "required": ["title", "version"],
            },
            "paths": {"type": "object"},
        },
    }
    good = '{"openapi": "3.0.0", "info": {"title": "X", "version": "1"}, "paths": {}}'
    bad = '{"openapi": "2.0", "info": {"title": "X", "version": "1"}, "paths": {}}'
    missing = '{"openapi": "3.0.0", "paths": {}}'
    assert run(good, schema=openapi) == []
    assert labels(bad, schema=openapi) == ["schema_violation"]
    assert labels(missing, schema=openapi) == ["schema_violation"]


# --------------------------------------------------------------------------- packaging


def test_the_detector_is_outside_core_and_declares_why() -> None:
    from flowx_border.detectors.catalogue import CATALOGUE, CORE

    assert "json_schema" not in CORE
    assert CATALOGUE["json_schema"].requires == {"dependency"}


def test_a_policy_enabling_it_gets_a_deployment_note() -> None:
    from flowx_border.policy import DetectorPolicy, Policy
    from flowx_border.registry import deployment_notes

    policy = Policy(
        policy_id="schema",
        version=1,
        fail_mode=dict.fromkeys(("T0", "T1", "T2", "T3"), "open"),
        detectors={
            "json_schema": DetectorPolicy(enabled=True),
            "sql_injection": DetectorPolicy(enabled=False),
            "url_reachability": DetectorPolicy(enabled=False),
        },
    )
    notes = deployment_notes(policy)
    assert len(notes) == 1
    assert "json_schema" in notes[0]


# --------------------------------------------------------------------------- plumbing


def test_no_finding_carries_a_span_or_the_failing_field() -> None:
    """A validation message quotes the offending value, and a record holds hashes.

    Putting the message in the finding would put the output inside the audit artifact,
    which is the one thing an evidence record must never contain.
    """
    schema = {
        "type": "object",
        "properties": {"customerReference": {"type": "string"}},
        "required": ["customerReference"],
    }
    # A distinctive field name, because `id` is a substring of `detector_id` and
    # `model_id` and an assertion about it would pass or fail for the wrong reason.
    for finding in run('{"customerReference": 998877}', schema=schema):
        assert finding.span is None
        payload = finding.model_dump_json()
        assert "customerReference" not in payload
        assert "998877" not in payload


def test_the_detector_matches_the_catalogue() -> None:
    from flowx_border.detectors.catalogue import CATALOGUE

    spec = CATALOGUE["json_schema"]
    assert (DETECTOR.id, DETECTOR.tier) == ("json_schema", spec.tier)
    assert DETECTOR.sides == spec.sides


def test_warm_is_idempotent() -> None:
    DETECTOR.warm()
    DETECTOR.warm()
    assert run('{"id": "A1", "total": 1}', schema=ORDER) == []
