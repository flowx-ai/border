# SPDX-License-Identifier: Apache-2.0
"""Tests for the model runtime and the two T1 detectors.

Real weights, no mocked sessions, per CLAUDE.md. Marked `slow` because they need the 279
MB INT8 artifact present, and skipped with a readable reason when it is not, so a fresh
clone does not fail a suite it was never able to run.

`HF_HUB_OFFLINE=1` is set for the whole module, which is doing double duty. It stops
huggingface-hub from making a revalidation request for a file it already has, and it
means these tests only pass if the library genuinely works with no network, which is
constraint 1. The socket guard in conftest.py would catch a violation anyway; this makes
the intent explicit rather than incidental.

The property worth the most here is offset correctness. A wrong span silently redacts
the wrong characters, and the caller cannot notice: the text still looks redacted.
"""

from __future__ import annotations

import itertools
import os

import pytest

os.environ.setdefault("HF_HUB_OFFLINE", "1")

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.catalogue import CATALOGUE
from flowx_border.detectors.output_leakage import OutputLeakageDetector
from flowx_border.detectors.pii import PiiDetector
from flowx_border.types import Finding

pytestmark = pytest.mark.slow

REDACT = DetectorConfig(on_fail="redact", threshold=0.5)


@pytest.fixture(scope="module")
def pii() -> PiiDetector:
    """A warmed PII detector, or a skip explaining what is missing."""
    from flowx_border.models.registry import ModelUnavailableError

    detector = PiiDetector()
    try:
        detector.warm()
    except ModelUnavailableError as error:
        pytest.skip(f"piiguard weights not cached: {error}")
    return detector


@pytest.fixture(scope="module")
def leakage(pii: PiiDetector) -> OutputLeakageDetector:
    # Depends on `pii` for ordering only: it warms the shared session first.
    detector = OutputLeakageDetector()
    detector.warm()
    return detector


def labels_and_text(
    detector: PiiDetector | OutputLeakageDetector,
    text: str,
    cfg: DetectorConfig = REDACT,
    ctx: Context | None = None,
) -> list[tuple[str, str]]:
    findings = detector.run(text, cfg, ctx or Context())
    return [
        (f.label, text[f.span[0] : f.span[1]]) for f in findings if f.span is not None
    ]


# --------------------------------------------------------------------------- offsets


def test_a_span_indexes_the_callers_string(pii: PiiDetector) -> None:
    # The property everything else rests on. A wrong span redacts the wrong characters
    # and the output still looks redacted, so nothing downstream can catch it.
    text = "Contact Marie Dubois about the claim."
    found = labels_and_text(pii, text)
    assert ("person", "Marie Dubois") in found


def test_the_second_occurrence_of_a_name_gets_its_own_span(pii: PiiDetector) -> None:
    # The regression this catches: reconstructing a span by searching the text for the
    # decoded token, which always finds the first occurrence.
    text = "Marie Dubois called. Please tell Marie Dubois we rang back."
    spans = [f.span for f in pii.run(text, REDACT, Context()) if f.label == "person"]
    assert len(spans) >= 2
    assert spans[0] != spans[1]
    for start, end in spans:
        assert text[start:end] == "Marie Dubois"


def test_an_entity_is_not_cut_in_half_by_the_model(pii: PiiDetector) -> None:
    # Measured on 2026-08-11: the tagger stopped at `bob.smith@example`, leaving
    # `.co.uk` outside the span. Redacting that produces `[EMAIL].co.uk`, which is a
    # leaked domain.
    text = "Write to bob.smith@example.co.uk today."
    covered = [value for _label, value in labels_and_text(pii, text)]
    assert "bob.smith@example.co.uk" in covered


def test_a_surname_is_not_cut_in_half(pii: PiiDetector) -> None:
    # Same failure, other shape: `Ion` tagged and `escu` not, redacting to
    # `[PERSON]escu`. Asserted as "no span ends inside a word" rather than on an exact
    # string, because whether the model returns `Ionescu` and `Bogdan` separately or
    # `Ionescu Bogdan` as one span is its business. Cutting a word in half is not.
    text = "Mă numesc Ionescu Bogdan."
    for finding in pii.run(text, REDACT, Context()):
        assert finding.span is not None
        start, end = finding.span
        # The character either side must not be alphanumeric, which is exactly what
        # "does not stop in the middle of a word" means. Trailing punctuation is fine.
        assert start == 0 or not text[start - 1].isalnum()
        assert end == len(text) or not text[end].isalnum()
    covered = " ".join(value for _label, value in labels_and_text(pii, text))
    assert "Ionescu" in covered


def test_no_span_falls_outside_the_text(pii: PiiDetector) -> None:
    text = "IBAN RO49AAAA1B31007593840000 and card 4111 1111 1111 1111."
    for finding in pii.run(text, REDACT, Context()):
        assert finding.span is not None
        start, end = finding.span
        assert 0 <= start < end <= len(text)


def test_spans_do_not_overlap_each_other(pii: PiiDetector) -> None:
    # Overlapping spans would make redaction order-dependent, which the engine's
    # right-to-left merge handles but should never have to.
    text = "Kovács Péter, e-mail: peter.kovacs@pelda.hu, telefon: +36 30 123 4567."
    spans = sorted(f.span for f in pii.run(text, REDACT, Context()) if f.span)
    for (_, first_end), (second_start, _) in itertools.pairwise(spans):
        assert first_end <= second_start


# ----------------------------------------------------------------- window boundaries


def test_an_entity_straddling_a_window_boundary_is_still_found(
    pii: PiiDetector,
) -> None:
    # The Phase 3 definition of done. A tiny window forces the boundary to land inside
    # the text many times over, so an entity is guaranteed to straddle one.
    filler = "Acesta este un text de umplutură despre programul de lucru. " * 6
    text = f"{filler}Vă rog contactați Ionescu Bogdan la ionescu.bogdan@example.ro."
    narrow = DetectorConfig(
        on_fail="redact",
        threshold=0.5,
        options={"window_tokens": 24, "window_overlap": 8},
    )
    found = labels_and_text(pii, text, narrow)
    assert any(value == "ionescu.bogdan@example.ro" for _label, value in found), found


def test_windowing_does_not_report_the_same_entity_twice(pii: PiiDetector) -> None:
    # Overlapping windows see boundary entities more than once, and two findings for one
    # entity would double-count it in the evidence record.
    filler = "Programul nostru de lucru este de luni până vineri. " * 6
    text = f"{filler}Contactați Ionescu Bogdan pentru detalii."
    narrow = DetectorConfig(
        on_fail="redact",
        threshold=0.5,
        options={"window_tokens": 24, "window_overlap": 8},
    )
    spans = [f.span for f in pii.run(text, narrow, Context())]
    assert len(spans) == len(set(spans))


def test_a_long_document_stays_linear_rather_than_truncated(pii: PiiDetector) -> None:
    # Windowing exists so a long input costs proportionally instead of being silently
    # cut at the model's max length. An entity at the very end has to survive.
    text = ("Vă mulțumim pentru mesajul dumneavoastră. " * 40) + "Semnat, Marie Dubois."
    found = labels_and_text(pii, text)
    assert ("person", "Marie Dubois") in found


# ----------------------------------------------------------------- session sharing


def test_the_two_t1_detectors_share_one_session(
    pii: PiiDetector, leakage: OutputLeakageDetector
) -> None:
    # The Phase 3 definition of done, and the reason output_leakage exists as a separate
    # detector at all: 279 MB twice for one model would be waste.  The claim is that
    # piiguard is loaded once, not that it is the only model in the process. The
    # stricter form of this held only while no other model could load, and broke the
    # moment a classifier warmed in the same session, which made it an assertion about
    # what else the suite had run rather than about session sharing.
    from flowx_border.models.onnx import loaded_model_ids, session_count

    assert leakage.shares_model_with == "piiguard"
    loaded = loaded_model_ids()
    assert loaded.count("piiguard") == 1, f"piiguard loaded more than once: {loaded}"
    assert session_count() == len(loaded), (
        f"{session_count()} sessions for {len(loaded)} models, so one loaded twice"
    )


def test_both_detectors_attest_the_same_weights(
    pii: PiiDetector, leakage: OutputLeakageDetector
) -> None:
    assert (pii.model_id, pii.model_revision) == (
        leakage.model_id,
        leakage.model_revision,
    )
    assert pii.weights_sha256 == leakage.weights_sha256
    assert len(pii.weights_sha256 or "") == 64


def test_warming_twice_does_not_load_twice(pii: PiiDetector) -> None:
    from flowx_border.models.onnx import session_count

    before = session_count()
    pii.warm()
    pii.warm()
    assert session_count() == before


def test_a_different_thread_count_is_a_different_session(pii: PiiDetector) -> None:
    # Documented behaviour rather than an accident: two detectors that disagree about
    # thread count genuinely need two sessions, because handing the second one a session
    # built for the first would make its latency unexplainable.
    from flowx_border.models.onnx import session_count, session_for

    before = session_count()
    session_for("piiguard", threads=2, verify=False)
    assert session_count() == before + 1


# --------------------------------------------------------------------- leakage logic


def test_leakage_reports_an_entity_the_caller_never_supplied(
    leakage: OutputLeakageDetector,
) -> None:
    text = "Your advisor is Marie Dubois, reachable at marie.dubois@bank.fr."
    ctx = Context(sources=("Your advisor is Marie Dubois.",))
    found = labels_and_text(leakage, text, ctx=ctx)
    assert ("leaked_email", "marie.dubois@bank.fr") in found


def test_leakage_does_not_report_an_entity_the_caller_did_supply(
    leakage: OutputLeakageDetector,
) -> None:
    # An assistant repeating back the address the user typed is not a leak, and
    # reporting it as one is how a detector gets switched off.
    text = "I have updated the address to marie.dubois@bank.fr as requested."
    ctx = Context(sources=("Please change my email to marie.dubois@bank.fr.",))
    assert not [label for label, _ in labels_and_text(leakage, text, ctx=ctx)]


def test_leakage_says_so_when_it_cannot_compare(leakage: OutputLeakageDetector) -> None:
    # No sources and no known_text: the check cannot run. Reporting nothing would look
    # exactly like a clean output, so it reports that it could not tell.
    findings = leakage.run("Contact marie.dubois@bank.fr.", REDACT, Context())
    assert [f.label for f in findings] == ["leakage_unverifiable"]
    # `log`, so an unconfigured caller is informed and not blocked.
    assert findings[0].action == "log"


def test_leakage_accepts_known_text_from_the_policy(
    leakage: OutputLeakageDetector,
) -> None:
    text = "Your advisor is Marie Dubois at marie.dubois@bank.fr."
    cfg = DetectorConfig(
        on_fail="flag", options={"known_text": "Marie Dubois, marie.dubois@bank.fr"}
    )
    assert not labels_and_text(leakage, text, cfg=cfg)


def test_leakage_comparison_ignores_case_and_spacing(
    leakage: OutputLeakageDetector,
) -> None:
    text = "Reach her at MARIE.DUBOIS@BANK.FR."
    ctx = Context(sources=("email:   marie.dubois@bank.fr",))
    assert not labels_and_text(leakage, text, ctx=ctx)


# ------------------------------------------------------------------------- options


def test_a_policy_can_narrow_the_entity_types(pii: PiiDetector) -> None:
    text = "Marie Dubois, marie.dubois@bank.fr, +33 6 12 34 56 78."
    only_email = DetectorConfig(on_fail="redact", options={"entities": ["email"]})
    labels = {label for label, _ in labels_and_text(pii, text, only_email)}
    assert labels == {"email"}


def test_an_unknown_entity_type_raises_rather_than_checking_nothing(
    pii: PiiDetector,
) -> None:
    with pytest.raises(ValueError, match="unknown entity type"):
        pii.run("x", DetectorConfig(options={"entities": ["creditcard"]}), Context())


def test_the_threshold_filters_findings(pii: PiiDetector) -> None:
    text = "Marie Dubois called about the claim."
    assert labels_and_text(pii, text, DetectorConfig(on_fail="flag", threshold=0.0))
    strict = DetectorConfig(on_fail="flag", threshold=1.0)
    for finding in pii.run(text, strict, Context()):
        assert finding.score >= 1.0


def test_empty_and_whitespace_input_produce_nothing(pii: PiiDetector) -> None:
    for text in ("", "   \n\t "):
        assert pii.run(text, REDACT, Context()) == []


def test_clean_text_produces_nothing(pii: PiiDetector) -> None:
    assert pii.run("What are your opening hours on Sunday?", REDACT, Context()) == []


# ------------------------------------------------------------------------- languages

# The 9 locales piiguard was actually trained on. The other 17 are deliberately absent:
# asserting on them would be asserting on behaviour nobody measured, and a green test
# would imply coverage the model does not have. See UNTESTED_LANGUAGES and task 12.
TRAINED = {
    "en": ("Please call Marie Dubois on +44 7700 900123.", "person"),
    "ro": ("Mă numesc Ionescu Bogdan și am CNP 1920304050607.", "national_id"),
    "bg": ("Иван Петров, имейл ivan@primer.bg.", "person"),
    "hu": ("Kovács Péter, e-mail: peter.kovacs@pelda.hu.", "email"),
    # A Steuer-IdNr rather than the German IBAN this used to carry. The IBAN was here to
    # check `national_id` and only did so because the model mislabelled it, so the day
    # the label got fixed the case stopped testing anything. See
    # test_the_checksum_pass_corrects_a_label_the_model_gets_wrong.
    "de": ("Herr Müller, Steuer-IdNr 86095742719.", "national_id"),
    "it": ("Contattare Marco Rossi al numero +39 06 1234 5678.", "person"),
    "fr": ("Contactez Marie Dubois, née le 12 mars 1985.", "person"),
    "hr": ("Ivan Horvat, e-pošta ivan.horvat@primjer.hr.", "email"),
    "sl": ("Janez Novak, e-pošta janez.novak@primer.si.", "email"),
}


@pytest.mark.parametrize("code", sorted(TRAINED))
def test_each_trained_language_finds_its_entity(pii: PiiDetector, code: str) -> None:
    text, expected = TRAINED[code]
    labels = {label for label, _ in labels_and_text(pii, text)}
    assert expected in labels, f"{code}: got {labels}"


def test_the_checksum_pass_corrects_a_label_the_model_gets_wrong(
    pii: PiiDetector,
) -> None:
    """A German IBAN used to come back as national_id, and now comes back as an IBAN.

    This file recorded the mislabelling for weeks on the argument that the number was
    covered either way and only the record's entity type was wrong. Both halves of that
    are now testable, which is the point of keeping one test over both numbers:

    The valid IBAN is relabelled, and not by the model. mod-97 says what it is, so
    `checksummed.py` overrules the tag and the record stops carrying a false statement.
    """
    text = "Herr Müller, IBAN DE89370400440532013000."
    found = {value: label for label, value in labels_and_text(pii, text)}
    assert found.get("DE89370400440532013000") == "iban"


def test_the_model_labels_an_iban_the_checksum_cannot_vouch_for(
    pii: PiiDetector,
) -> None:
    """The other half: change one digit so arithmetic cannot help, and read the raw tag.

    **This test used to assert the opposite, and the day it failed was the point of it.**
    It read `== "national_id"` and its docstring said "the day this fails, the model
    learned IBANs". That day was 2026-08-13, when the 26-locale retrain was adopted:
    held-out IBAN F1 goes 0.5913 to 0.9278, and this text is one of the cases that moved.

    So the pairing with the test above is inverted from what it was. It was written to
    prove the correction came from arithmetic rather than from the model, by showing the
    model still got it wrong wherever mod-97 declined to speak. Now the model gets it
    right unaided, and what the pair demonstrates instead is that the two mechanisms
    agree: `checksummed.py` overrules a valid IBAN's tag, and the tag it would have
    overruled is already correct.

    That is a weaker test than it was, and deliberately kept rather than deleted. The
    checksum pass is still the guarantee and the model is still only the recall net, so
    the assertion that matters is `test_the_checksum_pass_corrects_a_label_the_model_gets_wrong`
    above, which does not depend on the model being right about anything.

    The finding also survives: mod-97 fails, so the detector says so rather than passing
    a bad number through as a clean IBAN.
    """
    text = "Herr Müller, IBAN DE89370400440532013001."
    found = {value: label for label, value in labels_and_text(pii, text)}
    assert found.get("DE89370400440532013001") == "iban"

    # The checksum failure is reported, not swallowed. Without this the test would pass
    # on a detector that had stopped checking, which is the failure mode the whole
    # checksum pass exists to prevent.
    labels = {label for label, _ in labels_and_text(pii, text)}
    assert "pii_checksum_failed_iban" in labels


def test_a_spaced_card_number_is_covered_end_to_end(pii: PiiDetector) -> None:
    """The leak that caused `checksummed.py`, asserted against the real weights.

    Measured 2026-08-12 before the checksum pass: this text produced `national_id` over
    `4111` and a shape rejection over the next four digits, so twelve of the sixteen
    reached the caller unredacted. `tests/test_checksummed.py` covers the rule in
    isolation and this covers the thing that matters, which is that the detector a
    caller actually runs no longer leaves them there.
    """
    text = "Kartennummer 4111 1111 1111 1111 lautet auf Anna Schmidt."
    found = labels_and_text(pii, text)
    assert ("card", "4111 1111 1111 1111") in found

    # Nothing may report a fragment of it. A second span inside the card would mean the
    # old `national_id` finding survived, which is a false statement in the record even
    # though the redaction would still be complete.
    card = text.index("4111")
    inside = [
        (label, value)
        for label, value in found
        if value != "4111 1111 1111 1111" and value in text[card : card + 19]
    ]
    assert inside == []


def test_a_long_document_is_not_silently_truncated(pii: PiiDetector) -> None:
    """The tokenizer ships with truncation at 96 tokens and it must be disabled.

    Left on, `encode` returns the first 96 tokens of any input, so a 1701 character
    document was scanned to its first paragraph and the rest reported clean. This
    asserts the token count directly, because the symptom at the detector level is
    silence, which is indistinguishable from a clean document.
    """
    from flowx_border.detectors.pii import _tokenizer

    text = "Vă mulțumim pentru mesajul dumneavoastră. " * 40
    tokens = len(_tokenizer().encode(text, add_special_tokens=False).ids)
    assert tokens > 96, f"tokenizer truncated {len(text)} characters to {tokens} tokens"


def test_the_untested_languages_are_named_rather_than_implied(pii: PiiDetector) -> None:
    # 26 supported languages is not 26 tested languages, and the detector has to be able
    # to say which is which.
    from flowx_border.detectors.pii import TRAINED_LANGUAGES, UNTESTED_LANGUAGES

    assert len(TRAINED_LANGUAGES) == 9
    assert len(UNTESTED_LANGUAGES) == 17
    assert not TRAINED_LANGUAGES & set(UNTESTED_LANGUAGES)
    assert len(TRAINED_LANGUAGES | set(UNTESTED_LANGUAGES)) == 26


# ------------------------------------------------------------------------- contract


def test_both_detectors_match_the_catalogue(
    pii: PiiDetector, leakage: OutputLeakageDetector
) -> None:
    for detector in (pii, leakage):
        spec = CATALOGUE[detector.id]
        assert detector.tier == spec.tier
        assert detector.sides == spec.sides


def test_findings_carry_the_model_that_produced_them(pii: PiiDetector) -> None:
    # Without this the evidence record cannot say which weights made the decision.
    for finding in pii.run("Marie Dubois called.", REDACT, Context()):
        # Either the published repo or a local override, because the override is how the
        # weights are used before release and piiguard now ships from one: it was
        # re-exported on 2026-08-12 after its published INT8 was found to lose entities
        # its own fp32 weights find. What the record must never say is nothing.
        assert finding.model_id in ("flowxai/piiguard", "local/piiguard")
        # A commit sha for the published repo, or `local:` plus the leading hex of the
        # file's own hash for an override. The pattern in types.py admits exactly those
        # two and nothing else, so a record cannot claim a pinned revision for a file on
        # a laptop.
        assert finding.model_revision is not None
        assert finding.model_revision == "018e7f0355c0576938007c2bbfdd22d9275edbb9" or (
            finding.model_revision.startswith("local:")
        )


def test_a_finding_never_carries_the_matched_text(pii: PiiDetector) -> None:
    text = "Marie Dubois, marie.dubois@bank.fr"
    for finding in pii.run(text, REDACT, Context()):
        blob = finding.model_dump_json()
        assert "Dubois" not in blob
        assert "bank.fr" not in blob


def test_the_same_text_scans_identically_twice(pii: PiiDetector) -> None:
    # Constraint 6. INT8 inference is deterministic, and the session is configured
    # sequential so parallel reductions cannot reorder.
    text = "Herr Müller, IBAN DE89370400440532013000, geboren am 12.03.1985."
    first = pii.run(text, REDACT, Context())
    second = pii.run(text, REDACT, Context())
    assert first == second


def test_findings_are_ordered_by_position(pii: PiiDetector) -> None:
    # The evidence record lists findings in order, and a record whose order depended on
    # a dict would differ between two identical scans.
    text = "Marie Dubois, marie.dubois@bank.fr, +33 6 12 34 56 78."
    spans = [f.span for f in pii.run(text, REDACT, Context()) if f.span]
    assert spans == sorted(spans)


# --------------------------------------------------------------------------- runtime


def test_the_registry_refuses_a_branch_as_a_revision() -> None:
    # A branch name would let the weights change under a released library while the
    # evidence record kept attesting the same thing.
    from flowx_border.models.registry import ModelSpec

    with pytest.raises(ValueError, match="not a 40 character commit sha"):
        ModelSpec(
            model_id="x", repo="a/b", revision="main", filename="f", sha256="0" * 64
        )


def test_an_unpublished_model_names_the_repo_it_is_waiting_on() -> None:
    """An unpublished model must fail by name, rather than by returning nothing usable.

    Skipped per model when a local override supplies it, because then it is not
    unpublished from this process's point of view and there is nothing to assert. The
    override is how the models are used at all before release, so a test that assumed
    their absence was asserting on the state of a developer's disk.
    """
    from flowx_border.models.registry import (
        ModelUnavailableError,
        available,
        spec_for,
    )

    checked = 0
    for model_id in ("injection", "groundedness", "semantic-mapper"):
        if available(model_id):
            continue
        checked += 1
        with pytest.raises(ModelUnavailableError, match="ships unavailable"):
            spec_for(model_id)

    if checked == 0:
        pytest.skip("every named model is supplied by a local override")


def test_an_unknown_model_id_is_distinguishable_from_an_unbuilt_one() -> None:
    from flowx_border.models.registry import ModelUnavailableError, spec_for

    with pytest.raises(ModelUnavailableError, match="unknown model id"):
        spec_for("piigaurd")


def test_a_corrupted_weight_file_is_refused(
    tmp_path: object, monkeypatch: object
) -> None:
    # A truncated download and a substituted file look identical to a loader that only
    # checks the path exists.
    from flowx_border.models import registry

    fake = tmp_path / "model.int8.onnx"
    fake.write_bytes(b"not a model")
    monkeypatch.setattr(registry, "hf_hub_download", None, raising=False)
    monkeypatch.setattr("huggingface_hub.hf_hub_download", lambda **kwargs: str(fake))
    # The local override has to be out of the way, or `resolve` takes it and never
    # reaches the published path this test is about. That became live on 2026-08-12 when
    # piiguard started shipping from an override, and the test silently stopped checking
    # anything.
    monkeypatch.setattr(registry, "local_folder", lambda model_id: None)
    monkeypatch.setattr(registry, "local_spec_for", lambda model_id: None)
    with pytest.raises(registry.ModelUnavailableError, match="hashes to"):
        registry.resolve("piiguard")


def test_the_session_declares_the_inputs_the_detector_feeds(pii: PiiDetector) -> None:
    # Takes the fixture purely for its skip: every other test in this file gets a
    # readable reason when the weights are absent, and this one resolved the session
    # directly and failed in CI instead. piiguard takes input_ids and attention_mask and
    # no token_type_ids. Feeding an input the graph does not declare is an error, so the
    # feed is filtered against this.
    from flowx_border.models.onnx import session_for

    loaded = session_for("piiguard", verify=False)
    assert "input_ids" in loaded.input_names
    assert "attention_mask" in loaded.input_names


def test_findings_are_findings(pii: PiiDetector) -> None:
    for finding in pii.run("Marie Dubois called.", REDACT, Context()):
        assert isinstance(finding, Finding)
