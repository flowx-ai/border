# SPDX-License-Identifier: Apache-2.0
"""Tests for the secrets detector.

The false-positive tests matter more than the true-positive ones here, and the reason is
in the shipped default policy: `secrets: on_fail: block`, T0 cannot be disabled, and it
runs first on the input side. A false positive is a refused request the user cannot get
around. So the negative corpus is larger than the positive one, and it is deliberately
full of the high-entropy strings that occur in ordinary support tickets: UUIDs, git
SHAs, file paths, base64 image fragments, long URLs.

Every credential below is either a documented vendor example or a locally generated
string with the right shape. None is live.
"""

from __future__ import annotations

from typing import Final

import pytest

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.multilingual import LANGUAGES as CLAIMED
from flowx_border.detectors.secrets import SecretsDetector, shannon_entropy

DETECTOR = SecretsDetector()
CFG = DetectorConfig(on_fail="block")
CTX = Context()


def labels(text: str, cfg: DetectorConfig = CFG) -> list[str]:
    return [finding.label for finding in DETECTOR.run(text, cfg, CTX)]


def spans(text: str) -> list[tuple[int, int]]:
    return [f.span for f in DETECTOR.run(text, CFG, CTX) if f.span is not None]


# --------------------------------------------------------------------- named patterns


@pytest.mark.parametrize(
    ("label", "text"),
    [
        ("aws_access_key_id", "key is AKIAIOSFODNN7EXAMPLE ok"),
        ("aws_access_key_id", "ASIAY34FZKBOKMUTVV7A"),
        ("github_token", "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"),
        ("github_pat", "github_pat_" + "1" * 30),
        ("slack_token", "xoxb-263594206564-2343594206565-FGjklMNopQRstUVwxYZ"),
        (
            "slack_webhook",
            "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXX",
        ),
        ("google_api_key", "AIza" + "SyD-1234567890abcdefghijklmnopqrstu"),
        ("anthropic_api_key", "sk-ant-api03-" + "x" * 40),
        ("openai_api_key", "sk-proj-" + "abcdefghij1234567890ABCDEFGHIJ"),
        ("stripe_secret_key", "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"),
        ("private_key", "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."),
        ("private_key", "-----BEGIN OPENSSH PRIVATE KEY-----"),
        (
            "jwt",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N",
        ),
        ("basic_auth_url", "postgres://admin:hunter2hunter2@db.internal:5432/app"),
    ],
)
def test_a_named_credential_is_found(label: str, text: str) -> None:
    assert label in labels(text)


def test_a_named_pattern_scores_one() -> None:
    # Not a tuned number. A vendor prefix with the right length and alphabet is not a
    # probabilistic judgement.
    finding = DETECTOR.run("AKIAIOSFODNN7EXAMPLE", CFG, CTX)[0]
    assert finding.score == 1.0


def test_the_span_points_at_the_credential_and_nothing_else() -> None:
    text = "please rotate AKIAIOSFODNN7EXAMPLE today"
    start, end = spans(text)[0]
    assert text[start:end] == "AKIAIOSFODNN7EXAMPLE"


def test_the_action_comes_from_the_policy() -> None:
    assert (
        DETECTOR.run("AKIAIOSFODNN7EXAMPLE", DetectorConfig(on_fail="redact"), CTX)[
            0
        ].action
        == "redact"
    )


def test_a_stripe_publishable_key_is_not_a_secret() -> None:
    # pk_live_ is designed to sit in client-side code. Blocking a request for containing
    # one would be wrong, so it is deliberately absent from the pattern set.
    assert labels("pk_live_" + "4eC39HqLyjWDarjtT1zdp7dc") == []


def test_a_specific_vendor_key_is_not_also_reported_as_a_generic_one() -> None:
    # sk-ant-api03-... must not be reported as both anthropic and openai: one
    # credential, two findings, and the second tells the caller nothing.
    found = labels("sk-ant-api03-" + "y" * 40)
    assert found.count("anthropic_api_key") == 1
    assert "openai_api_key" not in found


def test_two_different_credentials_are_two_findings() -> None:
    text = "AKIAIOSFODNN7EXAMPLE and AIzaSyD-1234567890abcdefghijklmnopqrstu"
    assert sorted(labels(text)) == ["aws_access_key_id", "google_api_key"]


# ------------------------------------------------------------------ the entropy rule


def test_a_random_string_after_a_keyword_is_found() -> None:
    assert "high_entropy_string_near_keyword" in labels('API_KEY="Zk3Jf9dQ2xLm0PqR7"')


def test_the_same_string_with_no_keyword_is_not_reported() -> None:
    # Below the bare length floor. The keyword is what makes the guess worth making.
    assert labels("Zk3Jf9dQ2xLm0PqR7") == []


def test_a_long_mixed_random_string_is_reported_with_no_keyword() -> None:
    assert "high_entropy_string" in labels("Zk3Jf9dQ2xLm0PqR7sT4uV6wX8yA1bC2dE")


def test_a_long_ordinary_word_is_not_a_secret() -> None:
    # Long words in Hungarian and German reach the length floor easily. Requiring three
    # character classes is what separates them from a generated string.
    for word in (
        "megszentségteleníthetetlenségeskedéseitekért",
        "Donaudampfschifffahrtsgesellschaftskapitaen",
        "Rindfleischetikettierungsueberwachungsaufgabe",
    ):
        assert labels(word) == [], word


def test_the_entropy_score_is_the_normalised_entropy_not_one() -> None:
    # So that a policy can keep `block` for certain matches and have this rule report.
    finding = next(
        f
        for f in DETECTOR.run("Zk3Jf9dQ2xLm0PqR7sT4uV6wX8yA1bC2dE", CFG, CTX)
        if f.label.startswith("high_entropy")
    )
    assert 0.0 < finding.score < 1.0


def test_the_threshold_can_switch_the_entropy_rule_off() -> None:
    assert (
        labels("Zk3Jf9dQ2xLm0PqR7sT4uV6wX8yA1bC2dE", DetectorConfig(threshold=1.0))
        == []
    )


def test_a_named_match_is_not_also_reported_by_the_entropy_rule() -> None:
    found = labels("AKIAIOSFODNN7EXAMPLE")
    assert found == ["aws_access_key_id"]


# --------------------------------------------------- what must never be a secret


@pytest.mark.parametrize(
    "text",
    [
        # A UUID. Request ids and correlation ids look like this, and a support question
        # quoting one must not become a blocked request.
        "trace id 550e8400-e29b-41d4-a716-446655440000 please look it up",
        # A git object id and a sha256. A hash is not a credential.
        "broken since commit 9f2b8c1e4d7a6f3b0c5e8a2d1f4b7c9e0a3d6f8b",
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        # Paths, dotted names, versions, numbers.
        "/var/lib/containers/storage/overlay/abcdef0123456789/merged",
        "com.example.internal.billing.service.PaymentProcessorFactory",
        "version 1.2.3-rc.4+build.20260810123456",
        "reference number 4001234567890123456789",
        # A URL with a long path, which reaches the length floor.
        "https://example.com/reports/2026/quarterly-summary-north-region-final",
        # Ordinary prose in several languages, which is the common case.
        "Vă rog să verificați factura din luna trecută pentru contul meu.",
        "Kérem, ellenőrizze a számlámat a múlt hónapról a fiókomhoz.",
        "Proszę sprawdzić moją fakturę z ostatniego miesiąca na moim koncie.",
        "Lütfen hesabımdaki geçen ayın faturasını kontrol edin.",
        "Zəhmət olmasa hesabımdakı keçən ayın fakturasını yoxlayın.",
    ],
)
def test_ordinary_high_entropy_text_is_not_a_secret(text: str) -> None:
    assert labels(text) == [], text


def test_a_hex_digest_next_to_a_keyword_is_still_not_reported() -> None:
    # The keyword loosens the floors, and this is the case where that could go wrong:
    # "key" appears in prose about a cache key whose value is a hash.
    assert labels("the cache key is e3b0c44298fc1c149afbf4c8996fb92427ae41e4") == []


def test_an_empty_or_whitespace_input_produces_nothing() -> None:
    assert labels("") == []
    assert labels("   \n\t  ") == []


# ------------------------------------------------------------- non-English keywords


#: The word that means "a credential follows", in each of the 26 languages, around one
#: high entropy string. Every word here must also be in `_KEYWORDS` in the detector, and
#: that list already covered all 26 when this fixture was written: it was the test that
#: stopped at nine.
#: Worth having anyway rather than trusting the list. Greek is the precedent: the
#: literal "κωδικός" could never match casefolded input, because casefold rewrites the
#: final sigma, and nothing failed until a test ran the word through the detector. A
#: keyword list is only as good as the folding it survives.
ENTROPIC: Final = "Zk3Jf9dQ2xLm0PqR7"

KEYWORDS: dict[str, str] = {
    "en": f'password: "{ENTROPIC}"',
    "ro": f'parola mea este "{ENTROPIC}"',
    "bg": f'парола: "{ENTROPIC}"',
    "cs": f'heslo: "{ENTROPIC}"',
    "da": f'adgangskode: "{ENTROPIC}"',
    "de": f'Passwort: "{ENTROPIC}"',
    "el": f'κωδικός: "{ENTROPIC}"',
    "es": f'contraseña: "{ENTROPIC}"',
    "et": f'parool: "{ENTROPIC}"',
    "fi": f'salasana: "{ENTROPIC}"',
    "fr": f'ma clé: "{ENTROPIC}"',
    "ga": f'eochair: "{ENTROPIC}"',
    "hr": f'lozinka: "{ENTROPIC}"',
    "hu": f'jelszó = "{ENTROPIC}"',
    "it": f'la parola d\'ordine è "{ENTROPIC}"',
    "lt": f'slaptažodis: "{ENTROPIC}"',
    "lv": f'atslēga: "{ENTROPIC}"',
    "mt": f'passwerd: "{ENTROPIC}"',
    "nl": f'wachtwoord: "{ENTROPIC}"',
    "pl": f'hasło: "{ENTROPIC}"',
    "pt": f'senha: "{ENTROPIC}"',
    "sk": f'kluc: "{ENTROPIC}"',
    "sl": f'geslo: "{ENTROPIC}"',
    "sv": f'lösenord: "{ENTROPIC}"',
    "tr": f'şifre: "{ENTROPIC}"',
    "az": f'şifrə: "{ENTROPIC}"',
}


def test_the_keyword_fixtures_cover_every_language_the_project_claims() -> None:
    assert set(KEYWORDS) == CLAIMED


@pytest.mark.parametrize("code", sorted(KEYWORDS))
def test_a_credential_keyword_in_another_language_still_lowers_the_floor(
    code: str,
) -> None:
    # Without this the entropy rule is an English-only rule, and the library claims 26
    # languages on the input side.
    assert "high_entropy_string_near_keyword" in labels(KEYWORDS[code]), code


@pytest.mark.parametrize("code", sorted(KEYWORDS))
def test_the_keyword_lowers_the_floor_without_removing_it(code: str) -> None:
    """The other half, per language, so the sweep above is not vacuous.

    Adding 26 keywords to the detector risks the opposite failure: a keyword plus any
    string at all. So each language's keyword is kept and the credential is swapped for
    a string of one repeated character, whose entropy is zero. The keyword lowers the
    bar and the string still has to clear it.

    The first version of this test used "abcdefghijklmnop" as the benign string, which
    is sixteen distinct characters and therefore maximum entropy for its length. It
    failed in thirteen languages and the detector was right every time.
    """
    dull = ENTROPIC[0] * len(ENTROPIC)
    assert labels(KEYWORDS[code].replace(ENTROPIC, dull)) == [], code


# ----------------------------------------------------------------------- entropy fn


def test_entropy_of_a_uniform_string_is_zero() -> None:
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_entropy_is_bits_per_character_not_total() -> None:
    # So the threshold means the same thing for a 20 character token and an 80 character
    # one. Doubling a string leaves its per-character entropy unchanged.
    assert shannon_entropy("abcd") == pytest.approx(shannon_entropy("abcdabcd"))


def test_entropy_of_an_empty_string_is_zero_not_an_error() -> None:
    assert shannon_entropy("") == 0.0


def test_a_base64_like_string_scores_higher_than_prose() -> None:
    assert shannon_entropy("Zk3Jf9dQ2xLm0PqR7sT4uV") > shannon_entropy("please help me")


# --------------------------------------------------------------------------- contract


def test_the_detector_matches_the_catalogue() -> None:
    from flowx_border.detectors.catalogue import CATALOGUE

    spec = CATALOGUE["secrets"]
    assert (DETECTOR.id, DETECTOR.tier) == ("secrets", spec.tier)
    assert DETECTOR.sides == spec.sides


def test_warm_is_a_no_op_that_can_be_called_twice() -> None:
    DETECTOR.warm()
    DETECTOR.warm()
    assert labels("AKIAIOSFODNN7EXAMPLE") == ["aws_access_key_id"]


def test_findings_never_carry_the_matched_text() -> None:
    # Offsets, never the secret itself. A Finding is passed around by the caller and may
    # be logged, so the credential must not be inside it.
    for finding in DETECTOR.run("AKIAIOSFODNN7EXAMPLE", CFG, CTX):
        assert "AKIA" not in finding.model_dump_json()


def test_a_name_joined_to_a_national_id_is_not_a_secret() -> None:
    # Found by running the phase 2 definition of done: this fired as
    # `high_entropy_string` on a detector the default policy sets to `block`, so an
    # ordinary sentence became a refused request. It is also the wrong detector's job, a
    # national id belongs to `pii`.
    assert labels("my name is Ionescu-Bogdan-CNP-1920304050607") == []


@pytest.mark.parametrize(
    "text",
    [
        "invoice 2026-08-10-invoice-final-v2 attached",
        "order REF-2026-000148372-RO",
        "ticket SUPPORT-4471-ESCALATED-SECOND",
    ],
)
def test_separator_joined_identifiers_are_not_secrets(text: str) -> None:
    # Each segment is all letters or all digits, which is what a human compound
    # identifier looks like. Generated credentials interleave classes within a segment.
    assert labels(text) == [], text


def test_a_keyword_still_overrides_the_segment_heuristic() -> None:
    # With the keyword as evidence the heuristic is not needed, and suppressing there
    # would miss a real credential that happens to be hyphen-joined.
    assert "high_entropy_string_near_keyword" in labels("password: abcdefgh-12345678")
