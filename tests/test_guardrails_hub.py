# SPDX-License-Identifier: Apache-2.0
"""Tests for the Guardrails Hub inventory and the document rendered from it.

The inventory's only job is to be complete and to stay in step with the document, so
that is what is asserted. A port table that quietly lost a row would turn into a claim
that a validator was never considered, which is exactly the impression the file exists
to prevent.

The count is pinned at 65 deliberately. If the upstream repository grows a validator,
this test fails and somebody has to decide what to do with it, which is better than an
inventory that silently describes a snapshot nobody can date.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flowx_border.detectors.catalogue import CATALOGUE, CORE
from flowx_border.detectors.guardrails_hub import (
    DECLINED,
    PORTED,
    REASONS,
    all_validators,
    gaps,
    render_declined_table,
    render_ported_table,
    render_reasons_table,
)

DOC = (
    Path(__file__).resolve().parent.parent / "docs" / "porting-guardrails-validators.md"
)

#: The validator directories in guardrails-ai/guardrails-hub-monorepo as of 2026-08-11,
#: excluding `.github` and `scripts`, which are not validators.
HUB_COUNT = 65


# ------------------------------------------------------------------- completeness


def test_every_hub_validator_is_either_ported_or_declined() -> None:
    assert len(all_validators()) == HUB_COUNT


def test_no_validator_is_both_ported_and_declined() -> None:
    assert not set(PORTED) & set(DECLINED)


def test_every_port_names_a_detector_that_exists() -> None:
    # A port pointing at a detector id the catalogue does not have would be a claim
    # that something runs when nothing does.
    for name, entry in PORTED.items():
        assert entry.detector in CATALOGUE, f"{name} points at {entry.detector}"


def test_every_decline_uses_a_known_reason_code() -> None:
    for name, entry in DECLINED.items():
        assert entry.reason in REASONS, f"{name} has reason {entry.reason!r}"


def test_every_reason_code_is_used() -> None:
    # An unused code is a row in the rendered table that explains nothing.
    used = {entry.reason for entry in DECLINED.values()}
    assert set(REASONS) == used


def test_every_entry_carries_a_note() -> None:
    for name, entry in list(PORTED.items()) + list(DECLINED.items()):
        assert entry.note.strip(), f"{name} has no explanation"


def test_the_ported_detectors_are_all_represented() -> None:
    assert {entry.detector for entry in PORTED.values()} == {
        # summary_support joined on 2026-08-12, from extracted_summary_sentences_match,
        # which the hub answers with an OpenAI call and difflib answers for nothing.
        "summary_support",
        "banned_terms",
        "system_prompt_leakage",
        "markup_injection",
        "internal_domains",
        "output_format",
        "sql_injection",
        "url_reachability",
        "repetition",
        "json_schema",
    }


def test_the_gaps_are_the_declines_worth_revisiting() -> None:
    """Pinned, so flipping a gap flag is a deliberate edit with a test behind it.

    Fifteen since 2026-08-11, when the constraints stopped being prohibitions. Most of
    these were declined because a rule forbade them rather than because the check was
    not worth having, so lifting the rules turned them from refusals into a backlog.
    """
    # Twelve until 2026-08-11, when `valid_address` stopped being one: the half of
    # it that can be answered without a vendor is built as `postal_code`, and the
    # half that cannot is declined for good rather than pending.
    # Seven since extracted_summary_sentences_match was ported on 2026-08-12: the hub
    # asks an
    # LLM whether a summary's sentences appear in the source, and difflib answers the
    # same
    # question, so it became `summary_support` rather than staying a gap. What is left
    # is five
    # that need a local generative model and the two moderation retrains, and
    # docs/proposed-detectors.md recommends declining all seven for the reasons recorded
    # there.
    assert len(gaps()) == 7
    assert "llamaguard_7b" in gaps()
    assert "valid_address" not in gaps()
    # exclude_sql_predicates and valid_sql left this list on 2026-08-11 by being
    # built: they are `sql_injection`, the first detector outside CORE.
    assert "exclude_sql_predicates" not in gaps()
    # Nothing already answered by a detector is a gap: that would be a request to build
    # a second one.
    assert not [name for name in gaps() if DECLINED[name].reason == "covered"]


def test_every_covered_decline_names_a_detector_that_exists() -> None:
    # A `covered` note pointing at a detector id the catalogue does not have would be a
    # claim that a check runs somewhere when it runs nowhere.
    for name, entry in DECLINED.items():
        if entry.reason != "covered":
            continue
        assert any(f"`{known}`" in entry.note for known in CATALOGUE), (
            f"{name} is declined as covered but names no detector"
        )


# ------------------------------------------------------------------------ the document


def test_the_document_exists() -> None:
    assert DOC.exists(), "docs/porting-guardrails-validators.md is missing"


@pytest.mark.parametrize(
    "render", [render_reasons_table, render_ported_table, render_declined_table]
)
def test_each_rendered_table_appears_verbatim_in_the_document(render: object) -> None:
    """The anti-drift assertion, and the reason the tables are generated at all.

    Regenerate with:
        uv run python -m flowx_border.detectors.guardrails_hub
    """
    table = render()  # type: ignore[operator]
    assert table in DOC.read_text(encoding="utf-8"), (
        "the document no longer contains this table verbatim. Regenerate it rather "
        "than editing the table by hand."
    )


def test_the_document_names_every_validator() -> None:
    text = DOC.read_text(encoding="utf-8")
    for name in all_validators():
        assert f"`{name}`" in text, f"{name} is not named in the document"


def test_the_document_states_the_two_things_the_retrain_still_has_to_settle() -> None:
    """Retraining fixes the licence. It does not fix either of the other two.

    Neither is a reason not to do it, and both are things that go wrong silently if
    nobody writes them down: an unpinned generative detector produces a different
    verdict for the same input, and a 1.6B pass on CPU misses every budget in the table.
    """
    text = DOC.read_text(encoding="utf-8")
    assert "Pin decoding" in text
    assert "Give it a budget it can meet" in text


def test_the_document_frames_the_backlog_as_requirements_rather_than_refusals() -> None:
    # The reason codes double as the `Spec.requires` tags a built version would carry,
    # so the not-ported table is also the backlog. If that link is dropped the table
    # goes back to reading like a list of refusals.
    text = DOC.read_text(encoding="utf-8")
    assert "Spec.requires" in text


# ------------------------------------------------------------------------- packages


def test_only_the_detectors_that_declare_a_requirement_are_outside_core() -> None:
    """Core is the package that runs on a laptop with the interface down.

    One detector is outside it, `sql_injection`, which needs the sqlglot parser. Pinned
    by name so that a second one leaving core is a deliberate edit with a test behind
    it: leaving core changes what a caller has to provide before the detector will run
    at all, and that should never be something a change drifts into.
    """
    from flowx_border.detectors.catalogue import CORE

    assert set(CATALOGUE) - CORE == {
        "sql_injection",
        "url_reachability",
        "json_schema",
    }
    assert CATALOGUE["sql_injection"].requires == {"dependency"}
    assert CATALOGUE["json_schema"].requires == {"dependency"}
    assert CATALOGUE["url_reachability"].requires == {"network"}


def test_a_detector_declaring_a_requirement_is_reported_against_it() -> None:
    from flowx_border.detectors.catalogue import REQUIREMENTS, Spec, requirements_for

    # Built here rather than by mislabelling a real detector, because nothing shipped
    # today needs anything and asserting otherwise would be a false claim in a table.
    hosted = Spec("T2", frozenset({"output"}), 75.0, frozenset({"network", "gpu"}))
    assert hosted.requires == {"network", "gpu"}
    for requirement in hosted.requires:
        assert requirement in REQUIREMENTS

    # An id the catalogue does not carry contributes nothing rather than raising: this
    # reads a policy, and a policy naming an unknown id is the policy loader's error.
    assert requirements_for(["not_a_detector"]) == {}


def _policy(**detectors: object) -> object:
    from flowx_border.policy import DetectorPolicy, Policy

    return Policy(
        policy_id="notes-test",
        version=1,
        fail_mode=dict.fromkeys(("T0", "T1", "T2", "T3"), "open"),
        detectors={
            name: DetectorPolicy(enabled=bool(value))
            for name, value in detectors.items()
        },
    )


def test_the_two_requirement_codes_in_use_are_the_ones_declared() -> None:
    # The vocabulary in the catalogue and the vocabulary in the backlog are the same
    # words on purpose, so "this validator would need network" and "this detector needs
    # network" read as the same statement.
    from flowx_border.detectors.catalogue import REQUIREMENTS

    in_use = {
        requirement for spec in CATALOGUE.values() for requirement in spec.requires
    }
    assert in_use == {"dependency", "network"}
    assert in_use <= set(REQUIREMENTS)


def test_a_core_only_policy_produces_no_deployment_notes() -> None:
    """Silence is the common case and has to stay silent.

    A library that printed a note for every scan would train the caller to ignore the
    one that matters.
    """
    # Derived from CORE rather than named, so adding a non-CORE detector does not
    # silently turn this into a test that asserts nothing.
    from flowx_border.detectors.catalogue import CORE
    from flowx_border.registry import deployment_notes

    off = dict.fromkeys(set(CATALOGUE) - CORE, False)
    assert deployment_notes(_policy(**off)) == ()  # type: ignore[arg-type]


def test_a_policy_that_states_nothing_is_told_about_the_non_core_detector() -> None:
    """Defaults enable everything, so the default is that the caller is told.

    This is the direction the silence has to fail in. A policy that says nothing about
    `sql_injection` gets it enabled, and the note is how the caller learns they have
    taken on a parser dependency. The opposite default, silence unless asked, would put
    the discovery in production.
    """
    from flowx_border.detectors.catalogue import CORE
    from flowx_border.registry import deployment_notes

    notes = deployment_notes(_policy())  # type: ignore[arg-type]
    assert notes, "a policy that states nothing enables the non-CORE detectors"
    named = " ".join(notes)
    for detector_id in set(CATALOGUE) - CORE:
        assert detector_id in named, detector_id


def test_the_shipped_policies_stay_inside_core() -> None:
    from pathlib import Path

    from flowx_border import load_policy
    from flowx_border.registry import deployment_notes

    policies = Path(__file__).resolve().parent.parent / "policies"
    for path in sorted(policies.glob("*.yaml")):
        assert deployment_notes(load_policy(path)) == (), path.name


# ------------------------------------------------------------------------ moderation


def test_moderation_is_available_and_is_twelve_labels_of_thirteen() -> None:
    """Trained and published 2026-08-17, so the three tests here changed with it.

    They asserted the opposite until then: catalogued, absent, and an error explaining
    that what was missing was a corpus rather than a method. All three were correct and
    all three described a state that no longer exists, which is what a test asserting an
    absence does the day the absence ends.

    What replaces them is the claim worth holding: it is available, and it is twelve
    labels against a thirteen-label taxonomy. `child_safety` is deliberately untrained
    because the label covers sexualisation of minors and grooming. A head scoring zero
    on it while looking complete is the failure the "never silently do nothing" rule
    exists to prevent.
    """
    from flowx_border.models.registry import MODELS, UNPUBLISHED

    assert "moderation" in CATALOGUE
    assert "moderation" in MODELS, "published on 2026-08-17, so it belongs in MODELS"
    assert "moderation" not in UNPUBLISHED
    # `MODELS` and not `spec_for`. This read `spec_for("moderation")` until 2026-08-19,
    # which resolves the local override first, so with `FLOWX_BORDER_MODEL_DIR` set the
    # repo is a directory on the machine and the assertion below cannot hold. The claim
    # here is about what the published table says, and only the table can answer it.
    #
    # The same distinction `local_spec_for` exists to keep: a record from an override
    # reports `local:<sha>` and not a commit, precisely so a reader can tell them apart.
    # A test about the published entry has to read the published entry.
    spec = MODELS["moderation"]
    assert spec.repo == "flowxai/moderation"
    assert spec.trained_languages is not None
    assert len(spec.trained_languages) == 26
    assert "child_safety" in spec.notes, (
        "the registry note has to name the untrained label. A twelve-label head "
        "described as a moderation classifier, with nothing saying which of the "
        "thirteen is missing, is the omission this project refuses elsewhere."
    )


def test_moderation_ships_disabled_in_both_policies() -> None:
    """Available and off, which is a deliberate pair rather than an oversight.

    Measured the day it was published: it fires on 5 of 12 ordinary support questions at
    0.90 to 0.98, reading "How do I reset my password?" as `cyber_intrusion` at 0.97 and
    "How do I report a suspicious message I received?" as `sexual_exploitation` at 0.90.
    See tests/test_support_questions.py, where that is a strict xfail.

    So it is enabled by nobody until the corpus gains an account-access register, and a
    caller who wants to evaluate it on their own traffic turns it on in one line. Pinned
    because the tempting next step is to enable it now that it exists.
    """
    from flowx_border import load_policy

    for name in ("default", "bfsi"):
        policy = load_policy(f"policies/{name}.yaml")
        assert not policy.enabled_for("moderation"), (
            f"policies/{name}.yaml enables moderation, which fires on 5 of 12 ordinary "
            "support questions. See tests/test_support_questions.py."
        )


def test_the_retrain_entries_point_at_the_detector_that_replaces_them() -> None:
    for name in ("llamaguard_7b", "shieldgemma_2b"):
        assert DECLINED[name].reason == "retrain"


# ------------------------------------------------------- the counts stated in prose


def test_the_documents_prose_counts_match_the_code() -> None:
    """The assertion this file was missing, and the drift it would have
    caught.

    The three tables in the document are rendered from `PORTED`, `DECLINED` and
    `REASONS` and asserted verbatim above, so they cannot go stale. The sentences around
    them were maintained by hand, and by 2026-08-17 they said thirty-one became nine
    detectors with nine not built, when the code said thirty-two, ten and eight. Also
    "five of the seven are in CORE" when seven of the ten are.

    Every number a reader would quote is now checked, spelled the way the document
    spells it, because a count in prose that nothing verifies is the exact failure this
    repository has recorded most often.
    """
    text = DOC.read_text(encoding="utf-8")
    destinations = {port.detector for port in PORTED.values()}
    not_built = [name for name, entry in DECLINED.items() if entry.reason != "covered"]
    covered = [name for name, entry in DECLINED.items() if entry.reason == "covered"]
    in_core = {name for name in destinations if name in CORE}

    words = {
        5: "five",
        7: "seven",
        8: "eight",
        9: "nine",
        10: "ten",
        25: "twenty-five",
        31: "thirty-one",
        32: "thirty-two",
        33: "thirty-three",
    }

    def stated(number: int) -> str:
        word = words[number]
        return f"{word[0].upper()}{word[1:]}"

    expected = [
        (
            f"{stated(len(PORTED))} validators became "
            f"{words[len(destinations)]} detectors",
            "the ported total and how many detectors absorbed them",
        ),
        (f"{stated(len(covered))} are already answered", "the covered count"),
        (f"{stated(len(not_built))} are not built", "the not-built count"),
        (
            f"{words[len(in_core)].capitalize()} of the "
            f"{words[len(destinations)]} are in `CORE`",
            "how many destinations need nothing beyond a CPU",
        ),
        (
            f"{stated(len(PORTED))} validators, {words[len(destinations)]} detectors",
            "the restatement above the ported table",
        ),
    ]
    missing = [
        f"{why}: expected the document to say {phrase!r}"
        for phrase, why in expected
        if phrase not in text
    ]
    assert not missing, (
        "docs/porting-guardrails-validators.md states counts the code contradicts:\n  "
        + "\n  ".join(missing)
    )


def test_every_port_destination_is_a_real_detector() -> None:
    """A destination naming a detector that does not exist makes the table fiction."""
    unknown = sorted({p.detector for p in PORTED.values()} - set(CATALOGUE))
    assert not unknown, f"ported to detectors that are not catalogued: {unknown}"
