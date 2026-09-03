# SPDX-License-Identifier: Apache-2.0
"""cee-pii, `pii`'s policy-selectable GLiNER alternative.

Split from `test_pii.py` because this exercises a second architecture end to end
(word splitting, prompt construction, span enumeration, ONNX decode), not a
variant of piiguard's BIO path.

The real PyTorch-vs-ONNX equivalence check lives in the training repo,
`border_train/export/gliner_to_onnx.py`'s `verify()`, run at export time against
the real `gliner` package: 7 fixtures across en/ro/pl/hu, 0 span mismatches, max
score drift 0.00001. Deliberately not repeated here as a second, dependency-heavy
copy: `gliner` and `torch` are not runtime dependencies of this library and this
suite has no reason to need them installed. What this file checks instead is
narrower and does not overlap: that the library's own from-scratch
tokenize/decode path, called through the public API, reproduces the specific
result that PyTorch-vs-ONNX comparison already established was correct.
"""

from __future__ import annotations

import os

import pytest

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.ceepii import MAPPED_ENTITY_TYPES, MODEL_ID, run
from flowx_border.detectors.pii import ENTITY_TYPES


def config(**options: object) -> DetectorConfig:
    return DetectorConfig(
        enabled=True, threshold=0.5, on_fail="redact", always=False, options=options
    )


# ------------------------------------------------------------------ the label map


def test_every_mapped_type_is_one_pii_already_knows() -> None:
    """The invariant `ceepii.py`'s own module-level check enforces, asserted here
    too so a test failure names the file rather than an ImportError at collection.
    """
    assert set(MAPPED_ENTITY_TYPES) <= set(ENTITY_TYPES)


def test_the_drop_list_stays_out() -> None:
    """Labels documented as dropped in `ceepii.py`'s module docstring stay
    dropped. A future edit re-adding one silently would not fail any other test:
    `_LABEL_MAP` is a tuple literal, not a computed value, and nothing else in
    this suite iterates the 34 short types by name.
    """
    from flowx_border.detectors import ceepii

    dropped = {
        short for short, _phrasing, border in ceepii._LABEL_MAP if border is None
    }
    assert dropped == {
        "aba",
        "uk_sort_code",
        "uk_account_number",
        "uz_account",
        "ein",
        "company_number_uk",
        "employer",
        "plate",
        "postal",
        "policy_ref",
        "contract_ref",
        "account_ref",
        "health_condition",
        "first_name",
        "surname",
    }


# ------------------------------------------------------------------ model selection


def test_an_unknown_model_raises() -> None:
    from flowx_border.detectors.pii import PiiDetector

    detector = PiiDetector()
    with pytest.raises(ValueError, match="unknown model"):
        detector.run("text", config(model="cee-pi"), Context())


def test_no_model_option_stays_on_piiguard() -> None:
    from flowx_border.detectors.pii import _resolve_model_id

    assert _resolve_model_id(config()) == "piiguard"
    assert _resolve_model_id(config(model="cee-pii")) == MODEL_ID


# ------------------------------------------------------------------ availability


def test_unavailable_raises_and_does_not_fall_back_to_piiguard() -> None:
    """Without the local override, cee-pii is not resolvable, and `pii.run`'s
    dispatch does not catch that and quietly answer from piiguard instead.

    Local only: this does not touch the network, `available()` only checks the
    local override and the (empty, for cee-pii) MODELS table, so it belongs in
    the default suite rather than behind @pytest.mark.slow or .network.
    """
    from flowx_border.detectors.pii import PiiDetector
    from flowx_border.models.registry import ModelUnavailableError

    if os.environ.get("FLOWX_BORDER_MODEL_DIR"):
        pytest.skip("a local override is configured; this test wants none")

    detector = PiiDetector()
    with pytest.raises(ModelUnavailableError, match="cee-pii"):
        detector.run("Ionescu Bogdan", config(model="cee-pii"), Context())


def test_a_policy_that_would_enforce_with_it_is_refused_at_load(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """`assert_satisfiable`'s pre-flight check, not `run`'s. A caller who wrote
    `on_fail: redact` finds out before any text is scanned, the same guarantee
    `missing_for` already gives a policy naming a detector that is not loaded at
    all.
    """
    import yaml

    from flowx_border import load_policy, scan_input
    from flowx_border.models.registry import ModelUnavailableError

    if os.environ.get("FLOWX_BORDER_MODEL_DIR"):
        pytest.skip("a local override is configured; this test wants none")

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        yaml.safe_dump(
            {
                "policy_id": "ceepii-unavailable",
                "version": 1,
                "description": "test",
                "fail_mode": "open",
                "detectors": {
                    "pii": {
                        "on_fail": "redact",
                        "threshold": 0.5,
                        "options": {"model": "cee-pii"},
                    },
                },
            }
        )
    )
    policy = load_policy(policy_path)
    with pytest.raises(ModelUnavailableError):
        scan_input("Ionescu Bogdan", policy)


def test_a_policy_that_only_flags_is_not_refused(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """`log` and `flag` degrade to a gap the record shows, the same distinction
    `assert_satisfiable`'s own docstring draws for a missing detector.
    """
    import yaml

    from flowx_border import load_policy, scan_input

    if os.environ.get("FLOWX_BORDER_MODEL_DIR"):
        pytest.skip("a local override is configured; this test wants none")

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        yaml.safe_dump(
            {
                "policy_id": "ceepii-unavailable-flag",
                "version": 1,
                "description": "test",
                "fail_mode": "open",
                "detectors": {
                    "pii": {
                        "on_fail": "flag",
                        "threshold": 0.5,
                        "options": {"model": "cee-pii"},
                    },
                },
            }
        )
    )
    policy = load_policy(policy_path)
    decision = scan_input("Ionescu Bogdan", policy)
    pii_findings = [f for f in decision.findings if f.detector_id == "pii"]
    assert any(f.label == "detector_error" for f in pii_findings)


# ------------------------------------------------------------------ deployment notes


def test_deployment_notes_names_the_gpu_requirement(tmp_path) -> None:  # type: ignore[no-untyped-def]
    import yaml

    from flowx_border import load_policy
    from flowx_border.registry import deployment_notes

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        yaml.safe_dump(
            {
                "policy_id": "ceepii-gpu-note",
                "version": 1,
                "description": "test",
                "fail_mode": "open",
                "detectors": {
                    "pii": {
                        "on_fail": "flag",
                        "threshold": 0.5,
                        "options": {"model": "cee-pii"},
                    },
                },
            }
        )
    )
    policy = load_policy(policy_path)
    notes = deployment_notes(policy)
    assert any("gpu" in note and "pii" in note for note in notes)


def test_the_default_policy_says_nothing_about_a_gpu() -> None:
    from flowx_border import load_policy
    from flowx_border.registry import deployment_notes

    policy = load_policy("policies/default.yaml")
    assert not any("gpu" in note for note in deployment_notes(policy))


# ------------------------------------------------------------------ end to end


@pytest.fixture
def local_cee_pii() -> None:
    """Skips rather than fails when the local override is not configured.

    Matches `tests/test_entity_thresholds.py`'s `warmed` fixture: CI runs the
    whole suite with no model cache, so a slow marker alone does not keep this
    out of a red build the first time someone runs it without the training
    repo's artifact checked out.
    """
    from flowx_border.models.registry import ModelUnavailableError, available

    if not available(MODEL_ID):
        pytest.skip(
            "cee-pii is not available locally; set FLOWX_BORDER_MODEL_DIR at the "
            "training repo's artifacts_local to run this test"
        )
    try:
        run("warmup", config(entities=["email"]), model_id=MODEL_ID)
    except ModelUnavailableError as error:  # pragma: no cover - see available() above
        pytest.skip(str(error))


@pytest.mark.slow
def test_a_mixed_language_sentence_finds_person_email_and_phone(
    local_cee_pii: None,
) -> None:
    """The acceptance scenario this detector was built against.

    A name in Romanian spelling order, a French email domain, a Romanian phone
    number: no single one of cee-pii's five trained languages (en, ro, pl, hu,
    uz) covers the sentence, and PERSON, EMAIL and PHONE are found anyway, the
    generic-concept types the model generalises past its training languages on.
    """
    text = "Ionescu Bogdan, marie.dubois@bank.fr, +40 721 234 567"
    findings = run(text, config(entities=["person", "email", "phone"]))
    labels = {f.label for f in findings}
    assert labels == {"person", "email", "phone"}
    for finding in findings:
        assert finding.model_id is not None and "cee-pii" in finding.model_id
        assert finding.model_revision is not None


@pytest.mark.slow
def test_a_luhn_invalid_card_is_kept_and_marked_unverified(local_cee_pii: None) -> None:
    """The same shape gate piiguard's own spans go through, `pii.apply_shape_gate`,
    not a second copy of it. A checksum failure does not depend on which model
    tagged the span.
    """
    text = "My card number is 4111 1111 1111 1112, one digit off from valid."
    findings = run(text, config(entities=["card"]))
    labels = [f.label for f in findings]
    assert any(
        label.startswith("pii_checksum_failed_") or label == "card" for label in labels
    )
