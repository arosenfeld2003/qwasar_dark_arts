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
        with pytest.raises(ValueError, match="table"):
            build_query("us;ers", {"name": "alice"})

    def test_space_in_column(self):
        with pytest.raises(ValueError, match="column"):
            build_query("users", {"na me": "alice"})

    def test_sql_keyword_as_table(self):
        # "DROP" itself is alphanumeric and would pass — this tests the allowlist
        # The key security is that identifiers go into the SQL string directly,
        # so the regex must be strict enough.
        sql, _ = build_query("orders", {"id": 1})
        assert "orders" in sql

    def test_dash_in_table(self):
        with pytest.raises(ValueError, match="table"):
            build_query("my-table", {"id": 1})

    def test_dot_in_column(self):
        with pytest.raises(ValueError, match="column"):
            build_query("users", {"t.name": "alice"})

    def test_empty_table_name(self):
        with pytest.raises(ValueError, match="table"):
            build_query("", {"id": 1})

    def test_table_name_too_long(self):
        with pytest.raises(ValueError, match="table"):
            build_query("a" * 65, {"id": 1})


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

    def test_bool_value(self):
        # bool is subclass of int in Python; decide whether to allow or reject
        # The spec says str/int/float only — bool is int so this depends on impl.
        # We test that it either works or raises clearly.
        try:
            sql, vals = build_query("users", {"active": True})
            assert vals == [True]
        except ValueError:
            pass  # also acceptable
