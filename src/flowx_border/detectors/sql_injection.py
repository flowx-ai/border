# SPDX-License-Identifier: Apache-2.0
"""T1: SQL the model wrote that does more than the product asked for.

Ports two Guardrails Hub validators, `valid_sql` and `exclude_sql_predicates`. They are
the same check split in half: one asks whether the statement parses, the other asks
whether it holds constructs the deployment does not permit. Both need a parser, so they
are one detector here.

For a text-to-SQL product, this is the security check. The model is writing a statement
that will run against a real database, and the interesting failure is not that the SQL
is malformed, it is that a user talked the model into writing a second statement.

**This detector declares `requires={"dependency"}`.** It needs `sqlglot`, which is
not in the base install, so it is absent unless the `sql` extra is installed, and
`registry.deployment_notes` says so when a policy enables it. That is the packaging in
the packaging working as intended rather than a caveat: a text-to-SQL product wants
this and
takes the dependency, and everyone else neither pays for it nor hears about it.

Why a parser rather than a pattern
----------------------------------

Every regex-based SQL injection check has the same two failures, and both get worse in
26 languages, because a regex looks at the whole string while the danger lives only in
what is outside a string literal.

**It fires on ordinary text.** `SELECT * FROM vins WHERE region = 'Côte d''Or'` contains
the substring `'Or'`, so a check scanning for `' OR '` reports an injection in a query
about a French wine region. Every language here has words and place names that collide
with SQL keywords, and a check that fires on ordinary customer data gets switched off,
which leaves the real payload undetected. sqlglot parses that as one string literal and
this detector reports nothing.

**It misses the real thing.** Injection is not a keyword, it is a change of structure: a
second statement, a UNION onto a table the query had no business reading, a comparison
that is true whatever the data says. Those are facts about the parse tree. A pattern can
approximate them and a parser can answer them.

What it reports
---------------

    sql_unparseable          did not parse. Ports `valid_sql`.
    sql_stacked_statements   more than one statement. The classic injection.
    sql_forbidden_statement  a statement type the policy does not allow.
    sql_tautology            a comparison of two equal literals, `1=1` or `'a'='a'`.
    sql_set_operation        a UNION, INTERSECT or EXCEPT, when not allowed.

Options
-------

    allow:            list of statement kinds, default ["select"]. Ports
                      `exclude_sql_predicates` inverted: an allowlist rather than a
                      denylist, because a denylist of SQL statement types is a list
                      somebody has to keep complete, and the consequence of missing one
                      is a statement that runs.
    allow_union:      bool, default false.
    allow_tautology:  bool, default false.
    dialect:          sqlglot dialect name, default None for the generic parser.

Budget is 5 ms at p95 at the reference input. The reference input is prose rather than
SQL, so it fails to parse immediately, which is the cheap path. A long statement costs
more, and `tests/test_budgets.py` measures a realistic one separately.
"""

from __future__ import annotations

from types import ModuleType
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from sqlglot import expressions as exp

from flowx_border.detectors.base import OUTPUT, Context, DetectorConfig
from flowx_border.types import Finding

#: The extra that provides the parser, named in the error so the fix is in the message.
EXTRA: Final = "flowx-border[sql]"

#: Statement kinds a policy may allow, mapped to the sqlglot expression class name. A
#: fixed vocabulary rather than free text, so a policy typo is an error rather than a
#: silently permitted statement type.
_KINDS: Final[dict[str, str]] = {
    "select": "Select",
    "insert": "Insert",
    "update": "Update",
    "delete": "Delete",
    "merge": "Merge",
    "create": "Create",
    "drop": "Drop",
    "alter": "Alter",
    "truncate": "TruncateTable",
    "grant": "Grant",
    "command": "Command",
}

_SET_OPERATIONS: Final[frozenset[str]] = frozenset({"Union", "Intersect", "Except"})

DEFAULT_ALLOW: Final[tuple[str, ...]] = ("select",)


class SqlInjectionError(ValueError):
    """The policy asked for a check that cannot be performed as written."""


class SqlParserUnavailableError(RuntimeError):
    """`sqlglot` is not installed.

    Raised rather than degraded to a pass. A SQL safety check that quietly does nothing
    is worse than no check at all, because the caller believes generated statements are
    being inspected. The registry does not load this detector when the import fails, so
    in practice a policy enabling it gets `DetectorUnavailableError` at load time, which
    is earlier and louder than this.
    """


def _sqlglot() -> ModuleType:
    try:
        import sqlglot
    except ImportError as error:  # pragma: no cover - exercised by uninstalling it
        raise SqlParserUnavailableError(
            f"sql_injection needs the sqlglot parser, which is not installed. Install "
            f"{EXTRA}. This raises rather than passing, because a SQL check that "
            "silently does nothing leaves you believing generated statements are "
            "inspected when they are not."
        ) from error
    return sqlglot


def is_available() -> bool:
    """Whether the parser is importable. Used by the registry, not on the scan path."""
    try:
        _sqlglot()
    except SqlParserUnavailableError:
        return False
    return True


class SqlInjectionDetector:
    """Parses generated SQL and reports structure the policy does not permit."""

    id = "sql_injection"
    tier = "T1"
    sides = frozenset({OUTPUT})

    def warm(self) -> None:
        """Import the parser, so no scan pays for it. Idempotent."""
        _sqlglot()

    def run(
        self,
        text: str,
        cfg: DetectorConfig,
        ctx: Context,  # noqa: ARG002 - the Detector protocol fixes this signature
    ) -> list[Finding]:
        sqlglot = _sqlglot()
        options = cfg.options

        allow = self._allowed_kinds(options)
        allow_union = bool(options.get("allow_union", False))
        allow_tautology = bool(options.get("allow_tautology", False))
        dialect = options.get("dialect")

        if not text.strip():
            # An empty output is not malformed SQL, it is no SQL. Reporting
            # `sql_unparseable` for it would fire on every answer a policy applied this
            # detector to by mistake, which trains the reader to ignore the label.
            return []

        try:
            statements = [
                statement
                for statement in sqlglot.parse(text, dialect=dialect)
                if statement is not None
            ]
        except Exception:
            # sqlglot raises ParseError and also TokenError and RecursionError on some
            # inputs. Catching the class would let the others reach the engine, where
            # fail_mode would turn them into `detector_error` and lose the reason.
            return [self._finding("sql_unparseable", cfg)]

        if not statements:
            return [self._finding("sql_unparseable", cfg)]

        out: list[Finding] = []

        if len(statements) > 1:
            # The classic injection, and the one worth blocking on: the product asked
            # for a query and got a query plus something else.
            out.append(self._finding("sql_stacked_statements", cfg))

        for statement in statements:
            kind = type(statement).__name__
            if kind in _SET_OPERATIONS:
                if not allow_union:
                    out.append(self._finding("sql_set_operation", cfg))
            elif kind not in allow:
                out.append(self._finding("sql_forbidden_statement", cfg))

        if not allow_tautology and any(
            _has_tautology(statement) for statement in statements
        ):
            out.append(self._finding("sql_tautology", cfg))

        return out

    def _allowed_kinds(self, options: dict[str, Any]) -> frozenset[str]:
        raw = options.get("allow", DEFAULT_ALLOW)
        if isinstance(raw, str):
            raw = [raw]
        wanted = [str(kind).strip().lower() for kind in raw]
        unknown = sorted(set(wanted) - set(_KINDS))
        if unknown:
            raise SqlInjectionError(
                f"sql_injection does not know the statement kind(s) "
                f"{', '.join(unknown)}. Known: {', '.join(sorted(_KINDS))}. An unknown "
                "kind would be neither allowed nor forbidden, so it is rejected rather "
                "than guessed at."
            )
        return frozenset(_KINDS[kind] for kind in wanted)

    def _finding(self, label: str, cfg: DetectorConfig) -> Finding:
        return Finding(
            detector_id=self.id,
            tier=self.tier,
            label=label,
            # 1.0. Each of these is a fact about the parse tree rather than a guess.
            score=1.0,
            # No span. The finding is about the shape of the statement, and redacting a
            # fragment of SQL would produce a statement that is broken rather than safe.
            # A caller refuses the statement or runs it; there is no partial answer.
            span=None,
            action=cfg.on_fail,
        )


def _has_tautology(statement: exp.Expression) -> bool:
    """A comparison of two equal literals, anywhere in the tree.

    `1=1` and `'a'='a'` are the shape of an injected predicate that makes a WHERE clause
    true whatever the data says. Both sides must be literals: `id = id` is a column
    comparison that a real query can legitimately contain, and `region = 'Côte d''Or'`
    is a literal compared with a column, which is what every ordinary query looks like.
    """
    from sqlglot import exp

    for node in statement.find_all(exp.EQ, exp.NEQ):
        left, right = node.left, node.right
        if not isinstance(left, exp.Literal) or not isinstance(right, exp.Literal):
            continue
        same = left.this == right.this and left.is_string == right.is_string
        # `1=1` is a tautology, `1<>1` is a contradiction. Both are injected structure
        # rather than something a query generator writes, so both are reported.
        if isinstance(node, exp.EQ) and same:
            return True
        if isinstance(node, exp.NEQ) and not same:
            return True
    return False
