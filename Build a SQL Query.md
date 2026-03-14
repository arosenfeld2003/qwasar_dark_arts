## Query Filter Builder

Implement `build_query(table: str, filters: dict) -> tuple[str, list]` that returns a safe parameterized SQL query and its bound values.

The query format is:

```sql
SELECT * FROM <table> WHERE <key1> = ? AND <key2> = ?
```

Return a tuple: `(query_string, [value1, value2, ...])` — the values are **never** interpolated into the string.

### You must handle

- SQL keywords in values (`"' OR '1'='1"`, `"'; DROP TABLE users;--"`)  
- Comment injection in values (`"admin'--"`, `"admin'/*"`)  
- Tautologies (`"1 OR 1"`)  
- Malicious **table name** or **key name** (only allow alphanumeric \+ underscore)  
- Empty filters (return query with no WHERE clause)  
- Values that are not strings or numbers (reject them)

### Examples

```
build_query("users", {"name": "alice"})
→ ("SELECT * FROM users WHERE name = ?", ["alice"])

build_query("users", {"name": "' OR '1'='1"})
→ ("SELECT * FROM users WHERE name = ?", ["' OR '1'='1"])
# The injection is data, not code — safe because it's bound, not interpolated

build_query("us;ers", {"name": "alice"})
→ ERROR: invalid table name

build_query("users", {"na me": "alice"})
→ ERROR: invalid column name

build_query("users", {"role": ["admin", "user"]})
→ ERROR: value type not allowed
```

### Constraints

- Table and column names: only `[a-zA-Z0-9_]`, length 1–64  
- Values: only `str` or `int`/`float`  
- `0 <= len(filters) <= 20`

