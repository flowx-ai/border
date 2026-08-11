# SPDX-License-Identifier: Apache-2.0
"""Tests for the sql_injection detector.

The first block is the case that decides whether this detector is worth having: a
regex-based SQL injection check fires on ordinary customer data, and a parser does not.
`Côte d'Or` is a French wine region, and a query about it contains the substring `'Or'`,
so a check scanning for `' OR '` reports an injection. That is not a corner case; it is
what happens the first day the product is used in French.

The 26-language sweep is the same shape as the markup_injection one: a false-positive
sweep. Each language contributes a query whose string literal is ordinary text in that
language, and none of them may be reported.
"""

from __future__ import annotations

import re

import pytest

from flowx_border.detectors.base import Context, DetectorConfig
from flowx_border.detectors.sql_injection import (
    SqlInjectionDetector,
    SqlInjectionError,
    is_available,
)
from flowx_border.types import Finding

pytestmark = pytest.mark.skipif(
    not is_available(),
    reason="sqlglot not installed; sql_injection is outside CORE, install the extra",
)

DETECTOR = SqlInjectionDetector()
CTX = Context()


def run(text: str, **options: object) -> list[Finding]:
    return DETECTOR.run(text, DetectorConfig(on_fail="flag", options=options), CTX)


def labels(text: str, **options: object) -> list[str]:
    return [finding.label for finding in run(text, **options)]


#: The shape of check this detector replaces. Not a strawman: scanning for these
#: substrings is what a SQL injection check looks like without a parser.
NAIVE = re.compile(r"'\s*or\s*'|\bor\b\s+\d+\s*=\s*\d+|--|\bunion\b", re.IGNORECASE)


# --------------------------------------------------- why a parser rather than a pattern


def test_a_french_wine_region_is_not_an_injection() -> None:
    """The case that justifies the dependency.

    `Côte d'Or` is a real place. Escaped for SQL it is `'Côte d''Or'`, which contains
    `'Or'`, so a substring check reports an injection in an ordinary query. A check that
    fires on customer data gets switched off, and then the real payload is undetected.
    """
    sql = "SELECT * FROM vins WHERE region = 'Côte d''Or'"
    assert NAIVE.search(sql), "the naive check flags this, which is the whole point"
    assert run(sql) == []


def test_a_literal_containing_a_comment_marker_is_not_an_injection() -> None:
    sql = "SELECT * FROM notes WHERE body = 'range 2026-08-01 -- 2026-09-01'"
    assert NAIVE.search(sql)
    assert run(sql) == []


def test_a_real_injection_is_still_caught() -> None:
    found = labels("SELECT * FROM t WHERE id = 1 OR 1=1; DROP TABLE users")
    assert "sql_stacked_statements" in found
    assert "sql_tautology" in found
    assert "sql_forbidden_statement" in found


# ------------------------------------------------------------------ what it reports


def test_an_ordinary_select_is_clean() -> None:
    assert run("SELECT id, name FROM customers WHERE id = 42") == []


def test_unparseable_output_is_reported() -> None:
    # Ports `valid_sql`.
    assert labels("this is prose, not a statement at all") == ["sql_unparseable"]


def test_stacked_statements_are_reported() -> None:
    assert "sql_stacked_statements" in labels("SELECT 1; SELECT 2", allow=["select"])


def test_a_forbidden_statement_kind_is_reported() -> None:
    # Ports `exclude_sql_predicates`, inverted into an allowlist.
    assert "sql_forbidden_statement" in labels("DROP TABLE users")
    assert "sql_forbidden_statement" in labels("DELETE FROM users")
    assert "sql_forbidden_statement" in labels("UPDATE users SET admin = 1")


def test_a_policy_can_widen_the_allowed_kinds() -> None:
    assert run("DELETE FROM staging", allow=["select", "delete"]) == []


def test_an_unknown_statement_kind_raises_rather_than_being_ignored() -> None:
    # An unknown kind would be neither allowed nor forbidden, which is the silent
    # failure this project refuses.
    with pytest.raises(SqlInjectionError, match="does not know the statement kind"):
        run("SELECT 1", allow=["selct"])


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM t WHERE id = 1 OR 1=1",
        "SELECT * FROM t WHERE name = 'x' OR 'a'='a'",
        "SELECT * FROM t WHERE 2 <> 3",
    ],
)
def test_a_tautology_is_reported(sql: str) -> None:
    assert "sql_tautology" in labels(sql), sql


def test_a_column_compared_with_a_literal_is_not_a_tautology() -> None:
    # Which is what every ordinary query looks like.
    assert run("SELECT * FROM t WHERE region = 'Alsace'") == []


def test_a_column_compared_with_a_column_is_not_a_tautology() -> None:
    assert run("SELECT * FROM a JOIN b ON a.id = b.a_id") == []


def test_a_set_operation_is_reported_unless_allowed() -> None:
    sql = "SELECT name FROM t UNION SELECT password FROM users"
    assert "sql_set_operation" in labels(sql)
    assert run(sql, allow_union=True) == []


def test_a_tautology_can_be_allowed_for_a_generator_that_emits_one() -> None:
    assert run("SELECT * FROM t WHERE 1=1 AND id = 5", allow_tautology=True) == []


def test_an_empty_output_is_not_malformed_sql() -> None:
    # Reporting `sql_unparseable` for an empty string would fire on every answer a
    # policy applied this to by mistake, which trains the reader to ignore the label.
    assert run("") == []
    assert run("   \n ") == []


def test_a_dialect_can_be_named() -> None:
    assert run("SELECT TOP 1 * FROM t", dialect="tsql") == []


# --------------------------------------------------------------------- all 26 languages

#: Ordinary queries, one per language, whose string literal is real text in that
#: language. Several contain apostrophes, keyword-shaped words, or both, because those
#: are what a pattern-based check trips over.
CLEAN: dict[str, str] = {
    "en": "SELECT id FROM orders WHERE city = 'Newcastle upon Tyne'",
    "fr": "SELECT id FROM vins WHERE region = 'Côte d''Or'",
    "it": "SELECT id FROM eventi WHERE nome = 'Festa dell''Unione'",
    "ga": "SELECT id FROM aiteanna WHERE ainm = 'Contae Dhún na nGall'",
    "ro": "SELECT id FROM orase WHERE nume = 'Târgu Mureș'",
    "de": "SELECT id FROM staedte WHERE name = 'Baden-Württemberg'",
    "es": "SELECT id FROM ciudades WHERE nombre = 'A Coruña'",
    "pt": "SELECT id FROM cidades WHERE nome = 'São Tomé'",
    "nl": "SELECT id FROM steden WHERE naam = 's-Hertogenbosch'",
    "pl": "SELECT id FROM miasta WHERE nazwa = 'Świętochłowice'",
    "cs": "SELECT id FROM mesta WHERE nazev = 'Český Krumlov'",
    "sk": "SELECT id FROM mesta WHERE nazov = 'Banská Bystrica'",
    "sl": "SELECT id FROM mesta WHERE ime = 'Škofja Loka'",
    "hr": "SELECT id FROM gradovi WHERE ime = 'Šibenik'",
    "bg": "SELECT id FROM gradove WHERE ime = 'Велико Търново'",
    "el": "SELECT id FROM poleis WHERE onoma = 'Θεσσαλονίκη'",
    "hu": "SELECT id FROM varosok WHERE nev = 'Székesfehérvár'",
    "fi": "SELECT id FROM kaupungit WHERE nimi = 'Jyväskylä'",
    "sv": "SELECT id FROM stader WHERE namn = 'Växjö'",
    "da": "SELECT id FROM byer WHERE navn = 'Køge'",
    "et": "SELECT id FROM linnad WHERE nimi = 'Kärdla'",
    "lv": "SELECT id FROM pilsetas WHERE nosaukums = 'Jēkabpils'",
    "lt": "SELECT id FROM miestai WHERE pavadinimas = 'Šiauliai'",
    "mt": "SELECT id FROM ibliet WHERE isem = 'Birżebbuġa'",
    "tr": "SELECT id FROM sehirler WHERE ad = 'Şanlıurfa'",
    "az": "SELECT id FROM sheherler WHERE ad = 'Gəncə'",
}

CLAIMED = {
    "az",
    "bg",
    "cs",
    "da",
    "de",
    "el",
    "en",
    "es",
    "et",
    "fi",
    "fr",
    "ga",
    "hr",
    "hu",
    "it",
    "lt",
    "lv",
    "mt",
    "nl",
    "pl",
    "pt",
    "ro",
    "sk",
    "sl",
    "sv",
    "tr",
}


def test_the_fixtures_cover_every_language_the_project_claims() -> None:
    assert set(CLEAN) == CLAIMED


@pytest.mark.parametrize("code", sorted(CLEAN))
def test_an_ordinary_query_in_each_language_is_clean(code: str) -> None:
    assert run(CLEAN[code]) == [], f"{code}: {CLEAN[code]}"


@pytest.mark.parametrize("code", sorted(CLEAN))
def test_an_injection_appended_in_each_language_is_caught(code: str) -> None:
    # The literal stays ordinary text in that language, and the injection is structure.
    assert "sql_stacked_statements" in labels(f"{CLEAN[code]}; DROP TABLE users"), code


# --------------------------------------------------------------------------- packaging


def test_the_detector_is_outside_core_and_says_why() -> None:
    from flowx_border.detectors.catalogue import CATALOGUE, CORE

    assert "sql_injection" not in CORE
    assert CATALOGUE["sql_injection"].requires == {"dependency"}


def test_a_policy_enabling_it_gets_a_deployment_note() -> None:
    """The packaging working end to end, which is the point of declaring `requires`.

    A caller who turns this on is told at policy load that they have taken on a
    dependency, rather than finding out from an ImportError in production.
    """
    from flowx_border.policy import DetectorPolicy, Policy
    from flowx_border.registry import deployment_notes

    policy = Policy(
        policy_id="sql",
        version=1,
        fail_mode=dict.fromkeys(("T0", "T1", "T2", "T3"), "open"),
        detectors={"sql_injection": DetectorPolicy(enabled=True)},
    )
    notes = deployment_notes(policy)
    assert len(notes) == 1
    assert notes[0].startswith("dependency:")
    assert "sql_injection" in notes[0]


# --------------------------------------------------------------------------- plumbing


def test_the_detector_matches_the_catalogue() -> None:
    from flowx_border.detectors.catalogue import CATALOGUE

    spec = CATALOGUE["sql_injection"]
    assert (DETECTOR.id, DETECTOR.tier) == ("sql_injection", spec.tier)
    assert DETECTOR.sides == spec.sides


def test_warm_is_idempotent() -> None:
    DETECTOR.warm()
    DETECTOR.warm()
    assert run("SELECT 1") == []


def test_no_finding_carries_a_span() -> None:
    # Redacting a fragment of SQL produces a statement that is broken rather than safe.
    for finding in run("SELECT 1; DROP TABLE t"):
        assert finding.span is None


def test_findings_never_carry_the_text() -> None:
    for finding in run("SELECT * FROM accounts WHERE balance = 412; DROP TABLE t"):
        assert "412" not in finding.model_dump_json()
        assert "accounts" not in finding.model_dump_json()
