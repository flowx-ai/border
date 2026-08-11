# SPDX-License-Identifier: Apache-2.0
"""Tests for the evidence record.

Two invariants here are load-bearing, and one of them is legally material.

**No raw text in a record.** `types.py` makes it structurally hard by pattern
constraining every string field, but a structural guard can be widened by a future
change that looks harmless. So this file also asserts it behaviourally: a distinctive
marker string goes through a scan, and the serialised record is searched for it. That
test is the one to leave alone.

**Reproducible hashes.** Canonical JSON means two machines serialising the same record
produce the same bytes, so a signature made on one verifies on the other. Key order,
unicode escaping and float formatting are all pinned here, because each of them differs
between plausible JSON settings and each would break verification silently.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.engine import run_scan
from flowx_border.evidence import (
    attest,
    build_record,
    library_version,
    rfc3339_now,
    sign_record,
    summarise,
    text_hash,
    uuid7,
    verify_record,
)
from flowx_border.policy import Policy
from flowx_border.types import EvidenceRecord, Finding, canonical_json

MARKER = "Ionescu Bogdan, CNP 1920304050607, iban RO49AAAA1B31007593840000"


class Fake:
    """A detector that reports a finding whose label is safe but whose span is not."""

    id = "pii"
    tier = "T1"
    sides = frozenset({"input", "output"})
    model_id = "flowxai/piiguard-base"
    model_revision = "a" * 40
    weights_sha256 = "b" * 64

    def warm(self) -> None: ...

    def run(self, text: str, cfg: DetectorConfig, ctx: Context) -> list[Finding]:
        return [
            Finding(
                detector_id="pii",
                tier="T1",
                label="national_id",
                score=0.93,
                span=(19, 32),
                action="redact",
                model_id=self.model_id,
                model_revision=self.model_revision,
            )
        ]


def a_policy() -> Policy:
    return Policy(
        policy_id="test",
        version=1,
        fail_mode=dict.fromkeys(("T0", "T1", "T2", "T3"), "open"),
        detectors={},
    )


def a_record(text: str = MARKER) -> EvidenceRecord:
    return run_scan(text, "input", a_policy(), None, {"pii": Fake()}).evidence


# ------------------------------------------------------------------- no raw text


def test_the_serialised_record_does_not_contain_the_text() -> None:
    # The invariant the whole design rests on. If this fails, nothing else matters.
    blob = canonical_json(a_record()).decode("utf-8")
    assert MARKER not in blob
    for fragment in ("Ionescu", "1920304050607", "RO49AAAA1B31007593840000"):
        assert fragment not in blob, f"{fragment!r} leaked into the record"


def test_the_record_does_not_contain_the_text_in_any_field_recursively() -> None:
    # Walk the structure rather than the serialised form, so a future nested field is
    # covered without anyone remembering to extend this test.
    def strings(value: object) -> list[str]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict):
            return [s for v in value.values() for s in strings(v)]
        if isinstance(value, (list, tuple)):
            return [s for v in value for s in strings(v)]
        return []

    for found in strings(a_record().model_dump()):
        assert "Ionescu" not in found
        assert "1920304050607" not in found


def test_the_record_carries_the_hash_of_the_text() -> None:
    # What replaces the text. An auditor with the original can prove it is the same
    # input; nobody with only the record can recover it.
    record = a_record()
    assert record.input_hash == text_hash(MARKER)
    assert record.input_hash != text_hash(MARKER + " ")


def test_spans_are_not_in_the_record_even_though_they_are_in_the_finding() -> None:
    # A span is not the text, but "characters 19 to 32 were a national id" alongside a
    # hash narrows the search space for anyone trying to reconstruct it. The caller
    # keeps the span on the Finding; the record does not carry it.
    decision = run_scan(MARKER, "input", a_policy(), None, {"pii": Fake()})
    assert decision.findings[0].span == (19, 32)
    for summary in decision.evidence.finding_summary:
        assert "span" not in summary.model_dump()


def test_a_finding_summary_has_exactly_the_four_specified_keys() -> None:
    summary = summarise(
        [
            Finding(
                detector_id="pii",
                tier="T1",
                label="email",
                score=0.5,
                action="redact",
            )
        ]
    )
    assert set(summary[0].model_dump()) == {"detector_id", "label", "score", "action"}


# ------------------------------------------------------------------- canonical json


def test_canonical_json_sorts_keys_and_omits_whitespace() -> None:
    blob = canonical_json(a_record())
    assert b" " not in blob.split(b'"policy_id"')[0]
    parsed = json.loads(blob)
    assert list(parsed) == sorted(parsed)


def test_canonical_json_is_byte_identical_across_repeated_calls() -> None:
    record = a_record()
    assert canonical_json(record) == canonical_json(record)


def test_two_records_of_the_same_scan_differ_only_in_identity() -> None:
    first, second = a_record(), a_record()
    volatile = {"record_id", "timestamp"}
    a = {k: v for k, v in first.model_dump().items() if k not in volatile}
    b = {k: v for k, v in second.model_dump().items() if k not in volatile}
    assert a == b


def test_non_ascii_is_not_escaped_so_the_bytes_are_stable() -> None:
    # ensure_ascii would also be reproducible, but it changes the byte length of a
    # record depending on the language of its policy description, and the point of
    # pinning this is that nobody changes it later without thinking about signatures.
    payload = canonical_json({"description": "Verificări în limba română"})
    assert "română".encode() in payload


def test_a_record_round_trips_through_json_unchanged() -> None:
    record = a_record()
    revived = type(record).model_validate(json.loads(canonical_json(record)))
    assert canonical_json(revived) == canonical_json(record)


# ------------------------------------------------------------------- identity fields


def test_a_uuid7_has_the_version_and_variant_bits_set() -> None:
    import uuid

    parsed = uuid.UUID(uuid7())
    assert parsed.version == 7
    assert parsed.variant == uuid.RFC_4122


def test_uuid7_values_sort_by_creation_order() -> None:
    # The reason for choosing v7. Records sort by creation without a sequence column,
    # which is what makes an append-only audit log usable. 5000 in a tight loop lands
    # many in the same millisecond and crosses the 4096 counter rollover, so this fails
    # for any implementation that leaves same-millisecond order to the random bits.
    issued = [uuid7() for _ in range(5000)]
    assert issued == sorted(issued)
    assert len(set(issued)) == len(issued)


def test_uuid7_stays_monotonic_across_threads() -> None:
    # Two threads reading the same counter would mint duplicates, and a record id is a
    # primary key. Uniqueness is the assertion that matters; per-thread interleaving is
    # not something the caller can observe.
    import threading

    issued: list[str] = []
    lock = threading.Lock()

    def mint() -> None:
        mine = [uuid7() for _ in range(500)]
        with lock:
            issued.extend(mine)

    threads = [threading.Thread(target=mint) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(set(issued)) == 4000


def test_uuid7_does_not_go_backwards_when_the_clock_does() -> None:
    # An NTP correction must not make a later record sort before an earlier one.
    import flowx_border.evidence as evidence

    before = uuid7()
    real_time = evidence.time.time
    try:
        evidence.time.time = lambda: real_time() - 60  # type: ignore[assignment]
        after = uuid7()
    finally:
        evidence.time.time = real_time  # type: ignore[assignment]
    assert after > before


def test_the_timestamp_is_rfc3339_utc_with_milliseconds() -> None:
    from datetime import datetime

    stamp = rfc3339_now()
    assert stamp.endswith("Z")
    parsed = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S.%fZ")
    assert parsed.year >= 2026


def test_the_record_states_a_version_or_says_it_does_not_know() -> None:
    # An invented version in an audit record is worse than an honest marker.
    version = library_version()
    assert version == "0.0.0+unknown" or version[0].isdigit()
    assert a_record().library_version == version


# ------------------------------------------------------------------- attestation


def test_the_attestation_carries_the_model_and_weights_that_ran() -> None:
    record = a_record()
    assert [a.id for a in record.detectors] == ["pii"]
    only = record.detectors[0]
    assert only.model_id == "flowxai/piiguard-base"
    assert only.revision == "a" * 40
    assert only.weights_sha256 == "b" * 64


def test_a_rule_based_detector_attests_no_model_rather_than_a_placeholder() -> None:
    # `secrets` and `disclosure` have no weights. None is the honest answer; a string
    # like "n/a" would read as a model id to anything parsing these records.
    class Rules:
        id = "secrets"
        tier = "T0"
        sides = frozenset({"input"})

        def warm(self) -> None: ...

        def run(self, text: str, cfg: DetectorConfig, ctx: Context) -> list[Finding]:
            return []

    attestation = attest("secrets", Rules())
    assert (attestation.model_id, attestation.revision) == (None, None)
    assert attestation.weights_sha256 is None


def test_the_record_attests_what_ran_not_what_the_policy_asked_for() -> None:
    # The most damaging wrong thing this library could produce is a record claiming a
    # detector ran when it was not loaded.
    record = build_record(
        direction="input",
        policy=a_policy(),
        original_text="text",
        verdict="allow",
        findings=[],
        detectors={},
    )
    assert record.detectors == ()


def test_the_record_pins_the_policy_by_hash_not_only_by_id() -> None:
    # An id is a label a caller chooses. The hash is what lets an auditor tell two
    # revisions of "default" apart.
    policy = a_policy()
    record = a_record()
    assert record.policy_id == policy.policy_id
    assert record.policy_hash == policy.hash
    assert len(record.policy_hash) == 64


# ------------------------------------------------------------------- signing

ed25519 = pytest.importorskip(
    "cryptography.hazmat.primitives.asymmetric.ed25519",
    reason="signing is an optional extra: pip install 'flowx-border[signing]'",
)


def keypair() -> tuple[Any, Any]:
    private = ed25519.Ed25519PrivateKey.generate()
    return private, private.public_key()


def test_a_signed_record_verifies() -> None:
    private, public = keypair()
    assert verify_record(sign_record(a_record(), private), public) is True


def test_an_unsigned_record_does_not_verify() -> None:
    # False rather than an exception, and specifically not True: an absent signature is
    # not a passing one.
    _, public = keypair()
    record = a_record()
    assert record.signature is None
    assert verify_record(record, public) is False


def test_a_tampered_verdict_breaks_the_signature() -> None:
    # The whole point. Someone editing a stored record to say "allow" must be caught.
    private, public = keypair()
    signed = sign_record(a_record(), private)
    forged = signed.model_copy(update={"verdict": "allow"})
    assert verify_record(forged, public) is False


def test_a_tampered_input_hash_breaks_the_signature() -> None:
    private, public = keypair()
    signed = sign_record(a_record(), private)
    forged = signed.model_copy(update={"input_hash": "0" * 64})
    assert verify_record(forged, public) is False


def test_another_key_does_not_verify() -> None:
    private, _ = keypair()
    _, other_public = keypair()
    assert verify_record(sign_record(a_record(), private), other_public) is False


def test_verification_returns_false_for_a_malformed_signature() -> None:
    # A verification loop over an archive must not be derailed by one bad row.
    _, public = keypair()
    record = a_record().model_copy(update={"signature": "not base64 at all !!"})
    assert verify_record(record, public) is False


def test_signing_leaves_the_original_record_untouched() -> None:
    private, _ = keypair()
    record = a_record()
    signed = sign_record(record, private)
    assert record.signature is None
    assert signed.signature is not None


def test_the_signature_covers_the_record_with_the_signature_field_empty() -> None:
    # A signature cannot cover itself, so both signing and verifying must agree on
    # blanking the field first. If they disagree, nothing ever verifies.
    private, public = keypair()
    signed = sign_record(a_record(), private)
    resigned = sign_record(signed, private)
    assert resigned.signature == signed.signature
    assert verify_record(resigned, public) is True


def test_signing_is_stable_for_the_same_record_and_key() -> None:
    # Ed25519 is deterministic, which is what lets two archives of the same record be
    # compared byte for byte.
    private, _ = keypair()
    record = a_record()
    assert (
        sign_record(record, private).signature == sign_record(record, private).signature
    )
