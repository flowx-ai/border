# SPDX-License-Identifier: Apache-2.0
"""T1: output that does not match the schema the caller asked for.

Ports the Guardrails Hub `valid_open_api_spec` validator, and generalises it on the
way. That one validates output against a single schema, the OpenAPI meta-schema, which
is a narrow case of the useful thing: validating output against whichever schema the
product expects. Point this at the OpenAPI meta-schema and it is the original; point it
at your own and it is what you actually wanted.

**This declares `requires={"dependency"}`.** It needs `jsonschema`, which is the
`schema` extra rather than a base dependency, for the reason `sql_injection` needs
`sqlglot`: only a product with a schema wants it, and everyone else should neither pay
the install weight nor hear about it. The registry leaves it out when the extra is
absent, so a policy enabling it fails at load rather than mid-scan.

The schema lives in the policy, and that is not an accident
------------------------------------------------------------

Constraint 5 says policy is data, and a JSON Schema is data. So the schema goes in the
policy file, where a reviewer can read it and where `policy_hash` covers it: change the
schema and the hash changes, which is right, because the check changed.

The alternative, a path to a schema file, was rejected. It would let the behaviour of a
scan change without the policy hash changing, and every evidence record citing that
hash would be claiming to pin something it no longer pins.

What it reports
---------------

    not_json           the output does not parse as JSON at all
    schema_violation   it parses and does not satisfy the schema

A schema that is not itself a valid JSON Schema raises rather than reporting. It would
otherwise fail every output, and a caller reading a wall of `schema_violation` would
look for the fault in their model rather than in their policy.

`schema_violation` carries no span and does not name the field that failed. That is
deliberate: a validation message quotes the offending value, an evidence record holds
hashes rather than text, and putting the message in the finding would put the output
inside the audit artifact. The caller has both the output and the schema and can
reproduce the message in one line.

Budget is 5 ms at p95 at the reference input, which is prose and fails to parse at the
first character. A large document against a large schema costs more, and the ceiling
stays 5 ms because a schema check slower than a model pass would be a strange thing to
have.
"""

from __future__ import annotations

import json
from types import ModuleType
from typing import Final, cast

from flowx_border.detectors.base import OUTPUT, Context, DetectorConfig
from flowx_border.types import Finding

#: The extra that provides the validator, named in the error so the fix is in the
#: message.
EXTRA: Final = "flowx-border[schema]"


class JsonSchemaError(ValueError):
    """The policy asked for a check that cannot be performed as written."""


class SchemaValidatorUnavailableError(RuntimeError):
    """`jsonschema` is not installed.

    Raised rather than degraded to a pass, for the reason `sql_injection` gives: a check
    that quietly does nothing leaves the caller believing output is being validated.
    """


def _jsonschema() -> ModuleType:
    try:
        import jsonschema
    except ImportError as error:  # pragma: no cover - exercised by uninstalling it
        raise SchemaValidatorUnavailableError(
            f"json_schema needs the jsonschema package, which is not installed. "
            f"Install {EXTRA}. This raises rather than passing, because a schema check "
            "that silently does nothing leaves you believing output is validated when "
            "it is not."
        ) from error
    return cast(ModuleType, jsonschema)


def is_available() -> bool:
    """Whether the validator is importable.

    Used by the registry, never on the scan path.
    """
    try:
        _jsonschema()
    except SchemaValidatorUnavailableError:
        return False
    return True


class JsonSchemaDetector:
    """Validates the output against a schema the policy carries."""

    id = "json_schema"
    tier = "T1"
    sides = frozenset({OUTPUT})

    def warm(self) -> None:
        """Import the validator, so no scan pays for it. Idempotent."""
        _jsonschema()

    def run(
        self,
        text: str,
        cfg: DetectorConfig,
        ctx: Context,  # noqa: ARG002 - the Detector protocol fixes this signature
    ) -> list[Finding]:
        jsonschema = _jsonschema()
        schema = cfg.options.get("schema")

        if not schema:
            return [self._finding("schema_not_configured", cfg, action="log")]
        if not isinstance(schema, dict):
            raise JsonSchemaError(
                "json_schema options.schema must be a mapping, which is what a JSON "
                "Schema is. A path was considered and rejected: it would let a scan "
                "change behaviour without the policy hash changing."
            )

        validator_class = jsonschema.validators.validator_for(schema)
        try:
            validator_class.check_schema(schema)
        except jsonschema.exceptions.SchemaError as error:
            # A malformed schema would otherwise fail every output, and the caller would
            # look for the fault in their model rather than in their policy.
            raise JsonSchemaError(
                "json_schema options.schema is not a valid JSON Schema: "
                f"{error.message}"
            ) from error

        stripped = text.strip()
        if not stripped:
            # An empty output is not invalid JSON, it is no JSON. Reporting `not_json`
            # for it would fire on every answer a policy applied this to by mistake.
            return []

        try:
            document = json.loads(stripped)
        except (ValueError, RecursionError):
            return [self._finding("not_json", cfg)]

        validator = validator_class(schema)
        if next(validator.iter_errors(document), None) is not None:
            return [self._finding("schema_violation", cfg)]
        return []

    def _finding(
        self, label: str, cfg: DetectorConfig, action: str | None = None
    ) -> Finding:
        return Finding(
            detector_id=self.id,
            tier=self.tier,
            label=label,
            # 1.0. Either the document satisfies the schema or it does not.
            score=1.0,
            # No span, and no field name. A validation message quotes the offending
            # value, an evidence record holds hashes rather than text, and putting the
            # message in the finding would put the output inside the audit artifact.
            span=None,
            action=action or cfg.on_fail,
        )
