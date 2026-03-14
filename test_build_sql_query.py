import pytest
from build_sql_query import build_query


class TestHappyPath:
    def test_single_filter(self):
        sql, vals = build_query("users", {"name": "alice"})
        assert sql == "SELECT * FROM users WHERE name = ?"
        assert vals == ["alice"]

    def test_multiple_filters(self):
        sql, vals = build_query("users", {"name": "alice", "active": 1})
        assert "name = ?" in sql
        assert "active = ?" in sql
        assert "AND" in sql
        assert "alice" in vals
        assert 1 in vals

    def test_no_filters(self):
        sql, vals = build_query("products", {})
        assert sql == "SELECT * FROM products"
        assert vals == []

    def test_float_value(self):
        sql, vals = build_query("metrics", {"score": 9.5})
        assert vals == [9.5]

    def test_injection_string_is_safe_data(self):
        sql, vals = build_query("users", {"name": "' OR '1'='1"})
        assert sql == "SELECT * FROM users WHERE name = ?"
        assert vals == ["' OR '1'='1"]

    def test_drop_table_in_value_is_safe(self):
        sql, vals = build_query("users", {"name": "'; DROP TABLE users;--"})
        assert "DROP" not in sql
        assert vals == ["'; DROP TABLE users;--"]

    def test_underscore_in_table_name(self):
        sql, _ = build_query("user_accounts", {"id": 1})
        assert "user_accounts" in sql

    def test_underscore_in_column_name(self):
        sql, _ = build_query("users", {"first_name": "bob"})
        assert "first_name" in sql


class TestInvalidIdentifiers:
    def test_semicolon_in_table(self):
        with pytest.raises(ValueError, match="invalid table"):
            build_query("us;ers", {"name": "alice"})

    def test_space_in_column(self):
        with pytest.raises(ValueError, match="invalid column"):
            build_query("users", {"na me": "alice"})

    def test_dash_in_table(self):
        with pytest.raises(ValueError, match="invalid table"):
            build_query("my-table", {"id": 1})

    def test_dot_in_column(self):
        with pytest.raises(ValueError, match="invalid column"):
            build_query("users", {"t.name": "alice"})

    def test_empty_table_name(self):
        with pytest.raises(ValueError, match="invalid table"):
            build_query("", {"id": 1})

    def test_table_name_too_long(self):
        with pytest.raises(ValueError, match="invalid table"):
            build_query("a" * 65, {"id": 1})


class TestSQLKeywordIdentifiers:
    """
    Regression tests for vulnerability #1.

    SQL keywords pass the alphanumeric regex but produce syntactically ambiguous
    queries (SELECT * FROM DROP WHERE SELECT = ?) that can confuse parsers and
    DB engines.  They must be rejected.
    """

    def test_drop_as_table(self):
        with pytest.raises(ValueError, match="reserved SQL keyword"):
            build_query("DROP", {"name": "alice"})

    def test_select_as_column(self):
        with pytest.raises(ValueError, match="reserved SQL keyword"):
            build_query("users", {"SELECT": "x"})

    def test_union_as_column(self):
        with pytest.raises(ValueError, match="reserved SQL keyword"):
            build_query("users", {"UNION": "x"})

    def test_where_as_table(self):
        with pytest.raises(ValueError, match="reserved SQL keyword"):
            build_query("WHERE", {"id": 1})

    def test_insert_as_table(self):
        with pytest.raises(ValueError, match="reserved SQL keyword"):
            build_query("INSERT", {"id": 1})

    def test_keyword_check_is_case_insensitive(self):
        with pytest.raises(ValueError, match="reserved SQL keyword"):
            build_query("users", {"from": "x"})

    def test_non_keyword_alphanumeric_allowed(self):
        # "status", "type", "value" etc. are not reserved and must pass
        sql, _ = build_query("orders", {"status": "shipped"})
        assert "orders" in sql


class TestBoolRejection:
    """
    Regression tests for vulnerability #2.

    bool is a subclass of int; isinstance(True, int) is True. Without an
    explicit guard, True/False pass the type check and silently coerce to 1/0
    in the DB driver — a hidden type contract violation.
    """

    def test_true_rejected(self):
        with pytest.raises(ValueError, match="bool"):
            build_query("users", {"active": True})

    def test_false_rejected(self):
        with pytest.raises(ValueError, match="bool"):
            build_query("users", {"active": False})

    def test_int_one_still_allowed(self):
        sql, vals = build_query("users", {"active": 1})
        assert vals == [1]

    def test_int_zero_still_allowed(self):
        sql, vals = build_query("users", {"active": 0})
        assert vals == [0]


class TestOperators:
    """
    Tests for vulnerability #3 mitigation: operator allowlist.

    Rather than forcing callers to bypass build_query and construct raw SQL
    when they need LIKE or >, we accept (operator, value) tuples with an
    explicit allowlist of safe operators.
    """

    def test_greater_than(self):
        sql, vals = build_query("users", {"score": (">", 90)})
        assert "score > ?" in sql
        assert vals == [90]

    def test_like_operator(self):
        sql, vals = build_query("logs", {"msg": ("LIKE", "%error%")})
        assert "msg LIKE ?" in sql
        assert vals == ["%error%"]

    def test_not_like_operator(self):
        sql, vals = build_query("logs", {"msg": ("NOT LIKE", "%debug%")})
        assert "msg NOT LIKE ?" in sql

    def test_less_than_or_equal(self):
        sql, vals = build_query("products", {"price": ("<=", 99.99)})
        assert "price <= ?" in sql

    def test_not_equal(self):
        sql, vals = build_query("users", {"role": ("!=", "banned")})
        assert "role != ?" in sql

    def test_operator_case_normalized_to_upper(self):
        sql, _ = build_query("logs", {"msg": ("like", "%err%")})
        assert "LIKE" in sql

    def test_arbitrary_operator_rejected(self):
        with pytest.raises(ValueError, match="operator not allowed"):
            build_query("users", {"name": ("INJECT; DROP TABLE", "x")})

    def test_semicolon_in_operator_rejected(self):
        with pytest.raises(ValueError, match="operator not allowed"):
            build_query("users", {"id": ("= 1; DROP TABLE users; --", "x")})

    def test_malformed_tuple_rejected(self):
        with pytest.raises(ValueError):
            build_query("users", {"id": ("=", 1, "extra")})

    def test_mixed_plain_and_operator_filters(self):
        sql, vals = build_query("orders", {"status": "open", "total": (">", 100)})
        assert "status = ?" in sql
        assert "total > ?" in sql
        assert vals == ["open", 100]


class TestLimit:
    """
    Tests for vulnerability #4 mitigation: optional LIMIT clause.
    """

    def test_limit_appended(self):
        sql, vals = build_query("logs", {}, limit=100)
        assert sql == "SELECT * FROM logs LIMIT ?"
        assert vals == [100]

    def test_limit_with_filters(self):
        sql, vals = build_query("users", {"active": 1}, limit=50)
        assert "WHERE active = ?" in sql
        assert "LIMIT ?" in sql
        assert vals == [1, 50]

    def test_limit_zero_rejected(self):
        with pytest.raises(ValueError, match="limit"):
            build_query("users", {}, limit=0)

    def test_negative_limit_rejected(self):
        with pytest.raises(ValueError, match="limit"):
            build_query("users", {}, limit=-1)

    def test_bool_limit_rejected(self):
        with pytest.raises(ValueError, match="limit"):
            build_query("users", {}, limit=True)

    def test_no_limit_still_works(self):
        sql, vals = build_query("users", {"id": 1})
        assert "LIMIT" not in sql


class TestInvalidValues:
    def test_list_value(self):
        with pytest.raises(ValueError, match="type"):
            build_query("users", {"role": ["admin", "user"]})

    def test_dict_value(self):
        with pytest.raises(ValueError, match="type"):
            build_query("users", {"meta": {"key": "val"}})

    def test_none_value(self):
        with pytest.raises(ValueError, match="type"):
            build_query("users", {"name": None})


class TestErrorMessages:
    """
    Tests for vulnerability #5: error messages must not echo user input.

    In a web context, ValueError messages that propagate to HTTP responses
    or logs would leak user-controlled input (minor information disclosure).
    """

    def test_invalid_table_does_not_echo_input(self):
        payload = "us;ers<script>"
        with pytest.raises(ValueError) as exc_info:
            build_query(payload, {})
        assert payload not in str(exc_info.value)

    def test_invalid_column_does_not_echo_input(self):
        payload = "na me<script>"
        with pytest.raises(ValueError) as exc_info:
            build_query("users", {payload: "x"})
        assert payload not in str(exc_info.value)
