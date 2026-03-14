import re

_IDENTIFIER_RE = re.compile(r'^[a-zA-Z0-9_]{1,64}$')


def _validate_identifier(name: str, kind: str) -> None:
    if not _IDENTIFIER_RE.match(name):
        raise ValueError(f"ERROR: invalid {kind} name: {name!r}")


def build_query(table: str, filters: dict) -> tuple[str, list]:
    """
    Build a safe parameterized SQL SELECT query.
    Returns (query_string, bound_values).
    Table and column names must be alphanumeric + underscore only.
    Values must be str, int, or float.
    """
    _validate_identifier(table, "table")

    if len(filters) > 20:
        raise ValueError("ERROR: too many filters (max 20)")

    clauses = []
    values = []

    for col, val in filters.items():
        _validate_identifier(col, "column")
        if not isinstance(val, (str, int, float)):
            raise ValueError(f"ERROR: value type not allowed for key {col!r}")
        clauses.append(f"{col} = ?")
        values.append(val)

    if clauses:
        sql = f"SELECT * FROM {table} WHERE {' AND '.join(clauses)}"
    else:
        sql = f"SELECT * FROM {table}"

    return (sql, values)


if __name__ == "__main__":
    tests = [
        (("users", {"name": "alice"}),                     None),
        (("users", {"name": "' OR '1'='1"}),               None),
        (("us;ers", {"name": "alice"}),                    "invalid table"),
        (("users", {"na me": "alice"}),                    "invalid column"),
        (("users", {"role": ["admin", "user"]}),           "invalid value type"),
        (("users", {}),                                     None),
        (("users", {"id": 1, "active": 1.0}),              None),
        (("users", {"name": "'; DROP TABLE users;--"}),    None),
    ]

    for (args, expect_err) in tests:
        try:
            result = build_query(*args)
            status = "OK" if expect_err is None else "UNEXPECTED OK"
            print(f"[{status}] build_query{args} → {result}")
        except ValueError as e:
            status = "OK" if expect_err else "UNEXPECTED ERR"
            print(f"[{status}] build_query{args} → {e}")
