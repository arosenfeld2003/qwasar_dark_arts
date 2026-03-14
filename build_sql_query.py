import re

_IDENTIFIER_RE = re.compile(r'^[a-zA-Z0-9_]{1,64}$')

# Allowlist of operators that may appear in WHERE clauses.
# Keeping this as a frozenset means new operators must be explicitly approved.
_ALLOWED_OPERATORS = frozenset({
    "=", "!=", "<>", "<", ">", "<=", ">=",
    "LIKE", "NOT LIKE", "IS", "IS NOT",
})

# SQL reserved words that must not be used as table or column identifiers.
# Sourced from the SQL-92 / SQL:2016 reserved word lists. Using a keyword as
# an identifier is legal in some databases (with quoting) but we reject it
# outright because: (a) we don't quote identifiers, and (b) keyword-named
# columns produce syntactically ambiguous queries that can confuse parsers and
# downstream code.
_SQL_KEYWORDS = frozenset({
    "ADD", "ALL", "ALTER", "AND", "ANY", "AS", "ASC", "AUTHORIZATION",
    "BETWEEN", "BY", "CASCADE", "CASE", "CHECK", "COLUMN", "COMMIT",
    "CONSTRAINT", "CREATE", "CROSS", "CURRENT", "CURSOR", "DATABASE",
    "DEFAULT", "DELETE", "DESC", "DISTINCT", "DROP", "ELSE", "END",
    "EXCEPT", "EXISTS", "FOREIGN", "FROM", "FULL", "GRANT", "GROUP",
    "HAVING", "IN", "INDEX", "INNER", "INSERT", "INTERSECT", "INTO",
    "IS", "JOIN", "KEY", "LEFT", "LIKE", "LIMIT", "NOT", "NULL", "OF",
    "ON", "OR", "ORDER", "OUTER", "PRIMARY", "REFERENCES", "REPLACE",
    "RIGHT", "ROLLBACK", "SELECT", "SET", "SOME", "TABLE", "THEN",
    "TO", "TRANSACTION", "TRIGGER", "TRUNCATE", "UNION", "UNIQUE",
    "UPDATE", "USING", "VALUES", "VIEW", "WHEN", "WHERE", "WITH",
})


def _validate_identifier(name: str, kind: str) -> None:
    # Vulnerability fix #5: do not echo user input in error messages.
    if not _IDENTIFIER_RE.match(name):
        raise ValueError(f"ERROR: invalid {kind} name")
    # Vulnerability fix #1: block SQL reserved words as identifiers.
    if name.upper() in _SQL_KEYWORDS:
        raise ValueError(f"ERROR: {kind} name is a reserved SQL keyword")


def build_query(
    table: str,
    filters: dict,
    limit: int | None = None,
) -> tuple[str, list]:
    """
    Build a safe parameterized SQL SELECT query.
    Returns (query_string, bound_values).

    Parameters
    ----------
    table   : table name — alphanumeric + underscore, non-keyword, 1–64 chars
    filters : mapping of column → value  OR  column → (operator, value)
              Supported operators: = != <> < > <= >= LIKE NOT LIKE IS IS NOT
              Plain values default to the = operator.
    limit   : if provided, appends LIMIT ? to avoid full-table scans.
              Strongly recommended for production use; omitting it risks
              returning arbitrarily large result sets.

    Values must be str, int, or float.  bool is explicitly rejected (True/False
    silently coerce to 1/0 in most DB drivers, which is a hidden type contract
    violation).

    Examples
    --------
    build_query("users", {"name": "alice"})
    → ("SELECT * FROM users WHERE name = ?", ["alice"])

    build_query("users", {"score": (">", 90)}, limit=10)
    → ("SELECT * FROM users WHERE score > ? LIMIT ?", [90, 10])

    build_query("logs", {"msg": ("LIKE", "%error%")})
    → ("SELECT * FROM logs WHERE msg LIKE ?", ["%error%"])
    """
    _validate_identifier(table, "table")

    if len(filters) > 20:
        raise ValueError("ERROR: too many filters (max 20)")

    if limit is not None:
        if not isinstance(limit, int) or isinstance(limit, bool):
            raise ValueError("ERROR: limit must be a plain integer")
        if limit < 1:
            raise ValueError("ERROR: limit must be >= 1")

    clauses = []
    values = []

    for col, entry in filters.items():
        _validate_identifier(col, "column")

        # Unpack operator + value, or default to "="
        if isinstance(entry, tuple):
            if len(entry) != 2:
                raise ValueError("ERROR: filter tuple must be (operator, value)")
            op, val = entry
            if not isinstance(op, str) or op.upper() not in _ALLOWED_OPERATORS:
                raise ValueError("ERROR: operator not allowed")
            op = op.upper()
        else:
            op, val = "=", entry

        # Vulnerability fix #2: reject bool before the int check, because
        # bool is a subclass of int and isinstance(True, int) is True.
        if isinstance(val, bool):
            raise ValueError("ERROR: bool values are not allowed; use int 0/1 explicitly")
        if not isinstance(val, (str, int, float)):
            raise ValueError("ERROR: value type not allowed")

        clauses.append(f"{col} {op} ?")
        values.append(val)

    parts = [f"SELECT * FROM {table}"]
    if clauses:
        parts.append(f"WHERE {' AND '.join(clauses)}")
    # Vulnerability fix #4: optional LIMIT clause to prevent full-table dumps.
    if limit is not None:
        parts.append("LIMIT ?")
        values.append(limit)

    return (" ".join(parts), values)


if __name__ == "__main__":
    tests = [
        # (args, kwargs, expect_error)
        (("users", {"name": "alice"}),                          {},               None),
        (("users", {"name": "' OR '1'='1"}),                    {},               None),
        (("us;ers", {"name": "alice"}),                         {},               "invalid table"),
        (("users", {"na me": "alice"}),                         {},               "invalid column"),
        (("users", {"role": ["admin", "user"]}),                {},               "invalid value type"),
        (("users", {}),                                          {},               None),
        (("users", {"id": 1, "active": 1.0}),                   {},               None),
        (("users", {"name": "'; DROP TABLE users;--"}),         {},               None),
        # keyword identifiers
        (("DROP",  {"name": "alice"}),                          {},               "reserved keyword"),
        (("users", {"SELECT": "x"}),                            {},               "reserved keyword"),
        # bool rejection
        (("users", {"active": True}),                           {},               "bool"),
        (("users", {"active": False}),                          {},               "bool"),
        # operator support
        (("users", {"score": (">", 90)}),                       {},               None),
        (("logs",  {"msg":   ("LIKE", "%error%")}),             {},               None),
        (("users", {"name": ("INJECT; DROP", "x")}),            {},               "operator"),
        # limit
        (("logs",  {}),                                          {"limit": 100},   None),
        (("logs",  {"level": "ERROR"}),                          {"limit": 50},    None),
        (("logs",  {}),                                          {"limit": 0},     "limit >= 1"),
    ]

    for args, kwargs, expect_err in tests:
        try:
            result = build_query(*args, **kwargs)
            status = "OK" if expect_err is None else "UNEXPECTED OK"
            print(f"[{status}] build_query{args} {kwargs} → {result}")
        except ValueError as e:
            status = "OK" if expect_err else "UNEXPECTED ERR"
            print(f"[{status}] build_query{args} {kwargs} → {e}")
