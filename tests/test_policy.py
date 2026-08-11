# SPDX-License-Identifier: Apache-2.0
"""Tests for the policy layer.

The load-bearing property is the hash: two policies that mean the same thing must hash
the same, and two that mean different things must not. Everything an auditor does with a
record depends on that holding.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flowx_border.detectors.catalogue import CATALOGUE
from flowx_border.policy import DEFAULT_FAIL_MODE, Policy, PolicyError, load_policy

POLICIES = Path(__file__).resolve().parent.parent / "policies"

MINIMAL = """
policy_id: t
version: 1
detectors:
  pii:
    on_fail: redact
"""


def write(tmp_path: Path, body: str, name: str = "p.yaml") -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- shipped


def test_both_shipped_policies_load() -> None:
    for name in ("default.yaml", "bfsi.yaml"):
        policy = load_policy(POLICIES / name)
        assert policy.policy_id
        assert len(policy.hash) == 64


def test_bfsi_fails_closed_on_the_cheap_tiers_and_open_above() -> None:
    # The asymmetry is deliberate: failing closed on a 300 ms model that did not load
    # would take the assistant down, and the T0/T1 floor already holds.
    bfsi = load_policy(POLICIES / "bfsi.yaml")
    assert bfsi.fail_mode["T0"] == "closed"
    assert bfsi.fail_mode["T1"] == "closed"
    assert bfsi.fail_mode["T2"] == "open"
    assert bfsi.fail_mode["T3"] == "open"


def test_bfsi_blocks_regulated_advice_and_default_does_not() -> None:
    # This single difference is why bfsi.yaml exists.
    assert (
        load_policy(POLICIES / "bfsi.yaml").for_detector("regulated_advice").on_fail
        == "block"
    )
    assert (
        load_policy(POLICIES / "default.yaml").for_detector("regulated_advice").on_fail
        == "flag"
    )


def test_bfsi_runs_groundedness_every_time() -> None:
    assert (
        load_policy(POLICIES / "bfsi.yaml").for_detector("groundedness").always is True
    )
    assert (
        load_policy(POLICIES / "default.yaml").for_detector("groundedness").always
        is False
    )


# --------------------------------------------------------------------------- the hash


def test_reformatting_the_yaml_does_not_change_the_hash(tmp_path: Path) -> None:
    a = load_policy(write(tmp_path, MINIMAL, "a.yaml"))
    reordered = """
version: 1
detectors:
  pii: {on_fail: redact}
policy_id: t
"""
    b = load_policy(write(tmp_path, reordered, "b.yaml"))
    assert a.hash == b.hash


def test_stating_a_default_explicitly_does_not_change_the_hash(tmp_path: Path) -> None:
    # This is what makes the hash mean "same policy" rather than "same file".
    a = load_policy(write(tmp_path, MINIMAL, "a.yaml"))
    explicit = """
policy_id: t
version: 1
description: ""
detectors:
  pii:
    on_fail: redact
    enabled: true
    threshold: 0.5
    always: false
"""
    b = load_policy(write(tmp_path, explicit, "b.yaml"))
    assert a.hash == b.hash


def test_a_different_threshold_changes_the_hash(tmp_path: Path) -> None:
    a = load_policy(write(tmp_path, MINIMAL, "a.yaml"))
    b = load_policy(
        write(tmp_path, MINIMAL.replace("on_fail: redact", "threshold: 0.9"), "b.yaml")
    )
    assert a.hash != b.hash


def test_the_hash_is_stable_across_repeated_loads(tmp_path: Path) -> None:
    path = write(tmp_path, MINIMAL)
    assert load_policy(path).hash == load_policy(path).hash


def test_a_policy_cannot_declare_its_own_hash(tmp_path: Path) -> None:
    # A policy that could state its hash could lie about it.
    with pytest.raises(PolicyError):
        load_policy(write(tmp_path, MINIMAL + "\nhash: " + "0" * 64 + "\n"))


# --------------------------------------------------------------------------- rejection


def test_an_unknown_detector_id_is_an_error_not_a_warning(tmp_path: Path) -> None:
    # The failure this prevents: a typo silently disabling a check.
    body = (
        "policy_id: t\nversion: 1\ndetectors:\n  pii_detector:\n    on_fail: redact\n"
    )
    with pytest.raises(PolicyError, match="unknown detector"):
        load_policy(write(tmp_path, body))


def test_the_error_suggests_the_likely_intended_id(tmp_path: Path) -> None:
    body = "policy_id: t\nversion: 1\ndetectors:\n  pii_detector: {}\n"
    with pytest.raises(PolicyError, match="did you mean 'pii'"):
        load_policy(write(tmp_path, body))


def test_a_t0_detector_cannot_be_disabled(tmp_path: Path) -> None:
    body = "policy_id: t\nversion: 1\ndetectors:\n  secrets:\n    enabled: false\n"
    with pytest.raises(PolicyError, match="cannot be disabled"):
        load_policy(write(tmp_path, body))


def test_always_outside_t3_is_rejected_rather_than_ignored(tmp_path: Path) -> None:
    # Silently ignoring it would leave the author believing something was configured.
    body = "policy_id: t\nversion: 1\ndetectors:\n  pii:\n    always: true\n"
    with pytest.raises(PolicyError, match="only applies to T3"):
        load_policy(write(tmp_path, body))


def test_a_missing_policy_id_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="no policy_id"):
        load_policy(write(tmp_path, "version: 1\ndetectors: {}\n"))


def test_an_empty_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="empty"):
        load_policy(write(tmp_path, "\n"))


def test_invalid_yaml_names_the_file(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="not valid YAML"):
        load_policy(write(tmp_path, "policy_id: [unclosed\n"))


def test_a_missing_file_is_rejected_rather_than_defaulted(tmp_path: Path) -> None:
    # Scanning under a policy the caller did not write is worse than refusing to start.
    with pytest.raises(PolicyError, match="no policy file"):
        load_policy(tmp_path / "nope.yaml")


def test_a_threshold_outside_zero_to_one_is_rejected(tmp_path: Path) -> None:
    body = "policy_id: t\nversion: 1\ndetectors:\n  pii:\n    threshold: 1.5\n"
    with pytest.raises(PolicyError):
        load_policy(write(tmp_path, body))


# --------------------------------------------------------------------------- resolution


def test_every_catalogued_detector_appears_in_a_resolved_policy(tmp_path: Path) -> None:
    # The hash has to cover the whole decision surface. If a detector were absent from
    # the resolved document, adding it to the catalogue would not change any hash, and
    # two records taken before and after the change would look identical.
    policy = load_policy(write(tmp_path, MINIMAL))
    assert set(policy.detectors) == set(CATALOGUE)


def test_an_unmentioned_detector_gets_the_defaults(tmp_path: Path) -> None:
    policy = load_policy(write(tmp_path, MINIMAL))
    entry = policy.for_detector("toxicity")
    assert entry.enabled is True
    assert entry.threshold == 0.5
    assert entry.on_fail == "flag"


def test_a_single_fail_mode_value_expands_to_every_tier(tmp_path: Path) -> None:
    body = "policy_id: t\nversion: 1\nfail_mode: closed\ndetectors: {}\n"
    policy = load_policy(write(tmp_path, body))
    assert set(policy.fail_mode.values()) == {"closed"}
    assert len(policy.fail_mode) == 4


def test_fail_mode_defaults_to_open_when_unstated(tmp_path: Path) -> None:
    policy = load_policy(write(tmp_path, MINIMAL))
    assert set(policy.fail_mode.values()) == {DEFAULT_FAIL_MODE}


def test_a_detector_can_be_switched_off_with_a_bare_false(tmp_path: Path) -> None:
    body = "policy_id: t\nversion: 1\ndetectors:\n  toxicity: false\n"
    policy = load_policy(write(tmp_path, body))
    assert policy.enabled_for("toxicity") is False


def test_t0_is_enabled_even_when_the_file_never_mentions_it(tmp_path: Path) -> None:
    policy = load_policy(write(tmp_path, "policy_id: t\nversion: 1\ndetectors: {}\n"))
    assert policy.enabled_for("secrets") is True


def test_a_policy_is_immutable_once_loaded(tmp_path: Path) -> None:
    policy = load_policy(write(tmp_path, MINIMAL))
    with pytest.raises(Exception):  # noqa: B017 - pydantic frozen
        policy.policy_id = "other"  # type: ignore[misc]


def test_policy_can_be_constructed_directly_for_tests() -> None:
    # The engine tests need to build policies without touching the filesystem.
    policy = Policy(
        policy_id="t",
        version=1,
        fail_mode=dict.fromkeys(("T0", "T1", "T2", "T3"), "open"),
        detectors={},
    )
    assert policy.enabled_for("secrets") is True
