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

`HF_HUB_OFFLINE=1` is set for the whole module, matching `test_pii.py`'s
convention, for the same two reasons: it stops huggingface-hub revalidating a
cached file, and it makes the "unavailable" tests below deterministic rather than
dependent on a socket guard racing a real request. cee-pii moved from
`UNPUBLISHED` to `MODELS` on 2026-09-03, so "unavailable" no longer means "not
published" for it, the way it did while these tests were first written: it means
"not in the local HF cache", the same state every other published model is in on
a machine that has never scanned with it. The availability tests below force an
empty cache directory rather than trust whatever happens to be on the host
running them.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("HF_HUB_OFFLINE", "1")

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.ceepii import MAPPED_ENTITY_TYPES, MODEL_ID, run
from flowx_border.detectors.pii import BORDER_ENTITY_TYPES, ENTITY_TYPES


def config(**options: object) -> DetectorConfig:
    return DetectorConfig(
        enabled=True, threshold=0.5, on_fail="redact", always=False, options=options
    )


# ------------------------------------------------------------------ the label map


def test_the_vocabulary_is_exactly_what_the_two_models_produce() -> None:
    """The invariant `ceepii.py`'s own module-level check enforces, asserted here
    too so a test failure names the file rather than an ImportError at collection.

    Equality in both directions, which is stronger than the subset check this was
    until 2026-09-14. A type a model produces and no vocabulary names would reach a
    caller as a `[PLACEHOLDER]` nothing documents; a vocabulary entry no model
    produces is a type a policy can ask for and never be told is dead.
    """
    assert set(ENTITY_TYPES) | set(MAPPED_ENTITY_TYPES) == set(BORDER_ENTITY_TYPES)


def test_the_two_models_differ_by_organisation_and_only_by_it() -> None:
    """Pinned as a fact rather than left implicit, because it is the first time the
    two models have disagreed and every option-validation path below depends on it.

    `organisation` was mapped on 2026-09-14 from cee-pii's `employer or company name`
    label, which the library had been discarding. piiguard has no head for it, so the
    asymmetry is real and permanent until piiguard is retrained with one.
    """
    assert set(MAPPED_ENTITY_TYPES) - set(ENTITY_TYPES) == {"organisation"}
    assert set(ENTITY_TYPES) - set(MAPPED_ENTITY_TYPES) == set()


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
        "plate",
        "postal",
        "policy_ref",
        "contract_ref",
        "account_ref",
        "health_condition",
        "first_name",
        "surname",
    }


def test_piiguard_refuses_organisation_by_name_rather_than_finding_none() -> None:
    """The reason a type only one model produces is safe to add.

    A policy that names `organisation` while running piiguard is asking for a check
    that model cannot perform. Answering "nothing found" would be indistinguishable
    from a text with no company in it, which is the silent no-op rule 3 forbids and
    the same failure `wanted_entities` already refuses for a misspelled type. The
    error has to name the type and say what this model does tag, or a caller cannot
    tell a typo from a model that lacks the head.
    """
    from flowx_border.detectors.pii import wanted_entities

    with pytest.raises(ValueError, match="organisation") as raised:
        wanted_entities(config(entities=["person", "organisation"]))
    assert "card" in str(raised.value), (
        "the error has to list what this model does tag, or a caller cannot tell "
        "a misspelling from a missing head"
    )


def test_the_policy_reference_quotes_the_refusal_the_code_actually_raises() -> None:
    """`docs/concepts/the-policy-file.md` prints that error to show what a caller sees.

    A quoted message is a duplicate of a string in the code, and this repository's
    named failure mode is duplicates going stale while every test still agrees with
    itself. The document quotes the first two sentences, so this asserts the real
    message starts with what the document shows, rather than asserting the two are
    equal and forcing the document to carry a sentence about misspellings.
    """
    from pathlib import Path

    from flowx_border.detectors.pii import wanted_entities

    with pytest.raises(ValueError) as raised:
        wanted_entities(config(entities=["organisation"]))
    message = str(raised.value)

    document = Path("docs/concepts/the-policy-file.md").read_text(encoding="utf-8")
    quoted = (
        "pii: unknown entity type(s) organisation. This model tags card, date, email,\n"
        "    iban, location, national_id, person, phone."
    )
    assert quoted in document, "the policy reference no longer shows this refusal"
    assert message.startswith(quoted.replace("\n    ", " ")), (
        f"the policy reference quotes a message the code does not raise.\n"
        f"  document: {quoted.replace(chr(10) + '    ', ' ')!r}\n"
        f"  code    : {message!r}"
    )


def test_cee_pii_accepts_organisation() -> None:
    """The other half, which is what makes the refusal above a routing decision
    rather than the type being unusable. No model is loaded: this is option parsing.
    """
    from flowx_border.detectors.pii import (
        entity_actions,
        entity_thresholds,
        wanted_entities,
    )

    assert wanted_entities(
        config(entities=["organisation"]), MAPPED_ENTITY_TYPES
    ) == frozenset({"organisation"})
    assert entity_actions(
        config(entity_actions={"organisation": "flag"}), MAPPED_ENTITY_TYPES
    ) == {"organisation": "flag"}
    assert entity_thresholds(
        config(entity_thresholds={"organisation": 0.8}), MAPPED_ENTITY_TYPES
    ) == {"organisation": 0.8}


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


def test_unavailable_raises_and_does_not_fall_back_to_piiguard(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """cee-pii's bytes not being reachable does not fall back to piiguard.

    cee-pii moved from `UNPUBLISHED` to `MODELS` on 2026-09-03, so its own
    weights not being reachable is now the same class of event as piiguard's
    weights not being reachable: a real, published model whose bytes this
    process has not fetched yet. `hf_hub_download` is mocked to raise the same
    error `huggingface_hub` raises offline with nothing cached
    (`LocalEntryNotFoundError`), matching `test_pii.py`'s own
    `test_a_corrupted_weight_file_is_refused`, rather than trying to force an
    empty cache directory and race the real network.
    """
    from huggingface_hub.errors import LocalEntryNotFoundError

    from flowx_border.detectors.pii import PiiDetector
    from flowx_border.models import registry
    from flowx_border.models.registry import ModelUnavailableError

    def _refuse(**_kwargs: object) -> str:
        raise LocalEntryNotFoundError("not cached, offline")

    monkeypatch.setattr(registry, "hf_hub_download", None, raising=False)
    monkeypatch.setattr("huggingface_hub.hf_hub_download", _refuse)
    # The local override has to be out of the way, or `resolve` takes it and never
    # reaches the published path this test is about, the same caveat
    # `test_a_corrupted_weight_file_is_refused` carries.
    monkeypatch.setattr(registry, "local_folder", lambda model_id: None)
    monkeypatch.setattr(registry, "local_spec_for", lambda model_id: None)

    detector = PiiDetector()
    with pytest.raises(ModelUnavailableError, match="cee-pii"):
        detector.run("Ionescu Bogdan", config(model="cee-pii"), Context())


def test_a_policy_naming_an_unknown_model_is_refused_at_load(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """`assert_satisfiable`'s pre-flight check, not `run`'s. A caller who wrote
    `on_fail: redact` finds out before any text is scanned, the same guarantee
    `missing_for` already gives a policy naming a detector that is not loaded
    at all.

    Named with the same typo `test_an_unknown_model_raises` uses, "cee-pi",
    because cee-pii itself no longer demonstrates this: it moved from
    `UNPUBLISHED` to `MODELS` on 2026-09-03, so `available("cee-pii")` is now
    unconditionally true and this pre-flight check no longer flags it, which
    is correct. Every other model-backed detector already only pre-flight
    checks whether its model id is known at all, not whether its bytes happen
    to be cached on this process, and `pii`'s selectable model is now the same:
    "not yet cached" degrades at scan time, and only a genuinely unknown model
    name is refused before one starts.
    """
    import yaml

    from flowx_border import load_policy, scan_input
    from flowx_border.models.registry import ModelUnavailableError

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        yaml.safe_dump(
            {
                "policy_id": "ceepii-unknown-model",
                "version": 1,
                "description": "test",
                "fail_mode": "open",
                "detectors": {
                    "pii": {
                        "on_fail": "redact",
                        "threshold": 0.5,
                        "options": {"model": "cee-pi"},
                    },
                },
            }
        )
    )
    policy = load_policy(policy_path)
    with pytest.raises(ModelUnavailableError, match="unknown model id"):
        scan_input("Ionescu Bogdan", policy)


def test_a_policy_that_only_flags_is_not_refused(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """`log` and `flag` degrade to a gap the record shows, the same distinction
    `assert_satisfiable`'s own docstring draws for a missing detector. Same
    unknown-model scenario as the test above; see its docstring for why "cee-pi"
    rather than "cee-pii".
    """
    import yaml

    from flowx_border import load_policy, scan_input

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        yaml.safe_dump(
            {
                "policy_id": "ceepii-unknown-model-flag",
                "version": 1,
                "description": "test",
                "fail_mode": "open",
                "detectors": {
                    "pii": {
                        "on_fail": "flag",
                        "threshold": 0.5,
                        "options": {"model": "cee-pi"},
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


@pytest.mark.slow
def test_an_organisation_is_found_and_a_person_beside_it_survives(
    local_cee_pii: None,
) -> None:
    """The ninth entity type end to end, with the cost that mattered measured beside it.

    The risk in wiring a ninth prompt was not whether it works: it was whether it takes
    recall from `person`, which is what prompting `first_name` and `surname` alongside
    `person_name` was measured doing (see `_LABEL_MAP`'s comment). So this asserts both
    halves in one sentence, a company and a person in it, rather than testing the new
    type alone and leaving the regression to a number in a docstring.

    Measured across the 234 ordinary rows of `test_ordinary_text_sweep.py` before
    wiring: one person span changed and it was a false positive removed, 0 real people
    lost.
    """
    text = "Anna Kowalska is employed by Orlen S.A. in Warsaw."
    findings = run(text, config(entities=["person", "organisation"]))
    by_label = {f.label: text[f.span[0] : f.span[1]] for f in findings if f.span}
    assert "organisation" in by_label, f"no organisation finding in {findings}"
    assert "Orlen" in by_label["organisation"]
    assert by_label.get("person") == "Anna Kowalska"


@pytest.mark.slow
def test_organisation_is_absent_unless_the_policy_asks_for_it(
    local_cee_pii: None,
) -> None:
    """`options.entities` controls the prompt, so a policy that does not name
    `organisation` does not pay for the extra prompt column and cannot be surprised by
    a company name in its redacted output. That matters more for this type than for the
    other eight: a company name is not personal data, and 16 of 234 ordinary rows carry
    one, so a caller who did not ask for it and got it redacted would see 7 percent of
    ordinary business prose damaged by a correct finding.
    """
    text = "Anna Kowalska is employed by Orlen S.A. in Warsaw."
    findings = run(text, config(entities=["person"]))
    assert not [f for f in findings if f.label == "organisation"]
