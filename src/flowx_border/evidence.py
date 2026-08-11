# SPDX-License-Identifier: Apache-2.0
"""Building the evidence record, and signing it.

The record contains hashes, never text. `types.py` enforces that structurally (every
string field is pattern constrained, so there is nowhere for prose to sit) and
`tests/test_evidence.py` asserts it behaviourally with a marker string. This module is
where the hashes are computed.

One apparent conflict worth naming. Constraint 6 says a scan is deterministic given the
same inputs and model revisions, and this module stamps a timestamp and a fresh UUIDv7
into every record. Those are not behaviour: the verdict, the findings, the redacted text
and the policy hash are all determined by the inputs. `record_id` and `timestamp` say
*when this particular scan happened*, which is exactly the part that must differ between
two runs. Determinism applies to the decision, not to the identity of the audit row.

Signing is optional and the library never holds the key. `sign_record` takes a private
key the caller owns; nothing here generates, stores or reads one from disk. A library
that quietly managed signing keys would be a library that could forge evidence.
"""

from __future__ import annotations

import hashlib
import os
import struct
import threading
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flowx_border.types import (
    Decision,
    DetectorAttestation,
    Direction,
    EvidenceRecord,
    Finding,
    FindingSummary,
    Verdict,
    canonical_json,
)

if TYPE_CHECKING:
    from flowx_border.detectors.base import Detector
    from flowx_border.policy import Policy


def library_version() -> str:
    """The installed version, or a marker that says so rather than guessing."""
    try:
        return version("flowx-border")
    except PackageNotFoundError:  # pragma: no cover
        # Running from a source tree with no metadata. Say so in the record rather than
        # inventing a version an auditor might trust.
        return "0.0.0+unknown"


_UUID7_LOCK = threading.Lock()
# (milliseconds, counter) of the last value issued. Module level because monotonicity
# has to hold across every record this process writes, not per caller.
_UUID7_STATE = (0, 0)

_COUNTER_BITS = 12
_COUNTER_MAX = (1 << _COUNTER_BITS) - 1


def uuid7() -> str:
    """A version 7 UUID: 48 bits of Unix milliseconds, a 12 bit counter, then random.

    Written out because `uuid.uuid7` only arrived in the standard library in 3.14 and
    this package supports 3.11.

    The counter is RFC 9562 section 6.2 method 1, and it is not optional here. The
    time prefix has only millisecond resolution, so two records created in the same
    millisecond would be ordered by their random bits, which is to say arbitrarily. A
    T0 only scan has a 1 ms budget, so same millisecond records are the normal case
    rather than a corner one, and "records sort by creation order" is the property
    that lets an audit log be append only without a separate sequence column. Without
    the counter that claim is simply false.

    Three details earn their keep:

    - The counter sits in `rand_a`, immediately after the version nibble, so sorting
      the strings lexicographically sorts them by (millisecond, counter).
    - On counter overflow the timestamp borrows a millisecond from the future rather
      than sleeping. 4096 records inside one millisecond is far beyond what a CPU
      bound detector can produce, and a scan that stalled to preserve an ordering
      property would be the wrong trade.
    - A clock that steps backwards keeps the previous timestamp and advances the
      counter, so an NTP correction cannot make a later record sort before an
      earlier one.

    The lock is for correctness, not tidiness: two threads reading the same counter
    would mint duplicate ids, and a record id is a primary key.
    """
    global _UUID7_STATE

    with _UUID7_LOCK:
        now = int(time.time() * 1000) & 0xFFFF_FFFF_FFFF
        last_milliseconds, counter = _UUID7_STATE
        if now > last_milliseconds:
            milliseconds, counter = now, 0
        else:
            # Same millisecond, or the clock went backwards. Both are handled by holding
            # the previous timestamp and advancing the counter.
            milliseconds = last_milliseconds
            counter += 1
            if counter > _COUNTER_MAX:
                milliseconds += 1
                counter = 0
        _UUID7_STATE = (milliseconds, counter)

    # bytes 0-5: timestamp. byte 6: version 7 in the high nibble, then the counter's top
    # 4 bits. byte 7: the counter's low 8 bits. bytes 8-15: random, with the variant
    # bits set in byte 8.
    raw = bytearray(struct.pack(">Q", milliseconds)[2:])
    raw.append(0x70 | (counter >> 8))
    raw.append(counter & 0xFF)
    raw.extend(os.urandom(8))
    raw[8] = (raw[8] & 0x3F) | 0x80

    hexed = raw.hex()
    return f"{hexed[:8]}-{hexed[8:12]}-{hexed[12:16]}-{hexed[16:20]}-{hexed[20:]}"


def rfc3339_now() -> str:
    """UTC, millisecond precision, Z suffix. Matches the pattern in types.py.

    The clock is read once. Reading it twice, once for the date part and once for the
    milliseconds, produces a wrong timestamp whenever the two reads straddle a second
    boundary: 12:00:00.999 followed by 12:00:01.001 would be written as 12:00:00.001.
    Rare, and in an audit record a rare wrong timestamp is worse than a common one
    because nobody looks for it.
    """
    now = datetime.now(UTC)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def text_hash(text: str) -> str:
    """sha256 of the text, and the only thing about the text that enters a record."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def attest(detector_id: str, detector: Detector | None) -> DetectorAttestation:
    """What ran, and with which weights.

    A rule-based detector has no weights, so its model fields are None. That is the
    honest answer for `secrets` and `disclosure` rather than a placeholder that looks
    like a model.
    """
    model_id = getattr(detector, "model_id", None)
    revision = getattr(detector, "model_revision", None)
    weights = getattr(detector, "weights_sha256", None)
    return DetectorAttestation(
        id=detector_id,
        model_id=model_id,
        revision=revision,
        weights_sha256=weights,
    )


def summarise(findings: list[Finding]) -> tuple[FindingSummary, ...]:
    """The findings, stripped to what a record may carry.

    Spans are dropped. A span is an offset into the user's text, and while an offset is
    not the text, publishing "characters 41 to 63 were an IBAN" alongside a hash narrows
    the search space for anyone trying to reconstruct it. The finding keeps the span for
    the caller; the record does not.
    """
    return tuple(
        FindingSummary(
            detector_id=finding.detector_id,
            label=finding.label,
            score=finding.score,
            action=finding.action,
        )
        for finding in findings
    )


def build_record(
    *,
    direction: Direction,
    policy: Policy,
    original_text: str,
    verdict: Verdict,
    findings: list[Finding],
    detectors: Mapping[str, Detector],
) -> EvidenceRecord:
    """Assemble the record for one scan.

    `detectors` is what actually ran, not what the policy asked for. A record claiming a
    detector ran when it was not loaded would be the most damaging kind of wrong thing
    this library could produce.
    """
    return EvidenceRecord(
        record_id=uuid7(),
        timestamp=rfc3339_now(),
        direction=direction,
        policy_id=policy.policy_id,
        policy_hash=policy.hash,
        library_version=library_version(),
        detectors=tuple(attest(name, detectors[name]) for name in sorted(detectors)),
        input_hash=text_hash(original_text),
        verdict=verdict,
        finding_summary=summarise(findings),
        signature=None,
    )


# --------------------------------------------------------------------------- signing


@runtime_checkable
class Signer(Protocol):
    """The only thing this module needs from a private key.

    A protocol rather than the cryptography type, for two reasons. It keeps
    `cryptography` an optional dependency of signing rather than of importing. And it
    lets a caller pass an HSM handle, a KMS client shim, or anything else that signs
    the same bytes, which matters because the library never holds the key and so has
    no business naming its class.
    """

    def sign(self, data: bytes) -> bytes: ...


@runtime_checkable
class Verifier(Protocol):
    """The only thing this module needs from a public key: raise or return."""

    def verify(self, signature: bytes, data: bytes) -> None: ...


def sign_record(record: EvidenceRecord, private_key: Signer) -> EvidenceRecord:
    """Return a copy of the record carrying a signature over its canonical JSON.

    The signature covers the record with `signature` set to None, which is the only
    self-consistent choice: a signature cannot cover itself. `verify_record` reproduces
    that form before checking.

    The key is the caller's. This function does not generate, store, cache or look for
    one.
    """
    import base64

    unsigned = record.model_copy(update={"signature": None})
    payload = canonical_json(unsigned)
    signature = private_key.sign(payload)
    return record.model_copy(
        update={"signature": base64.b64encode(signature).decode("ascii")}
    )


def verify_record(record: EvidenceRecord, public_key: Verifier) -> bool:
    """True when the signature matches the record. False for any failure, never an
    exception, so a verification loop over an archive cannot be derailed by one bad row.
    """
    import base64

    if record.signature is None:
        return False

    try:
        from cryptography.exceptions import InvalidSignature
    except ImportError:  # pragma: no cover
        raise ImportError(
            "verifying a record needs the 'cryptography' package. It is in the allowed "
            "runtime set; install it with: pip install 'flowx-border[signing]'"
        ) from None

    unsigned = record.model_copy(update={"signature": None})
    try:
        public_key.verify(base64.b64decode(record.signature), canonical_json(unsigned))
    except (InvalidSignature, ValueError):
        return False
    return True


def record_of(decision: Decision) -> EvidenceRecord:
    """Convenience for callers who archive the record and discard the text."""
    return decision.evidence
