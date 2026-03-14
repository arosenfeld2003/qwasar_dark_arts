## Log Entry Formatter

Implement `format_log(level: str, message: str, context: dict) -> str` that produces a single-line log entry:

```
[LEVEL] message key1=value1 key2=value2
```

The output must be **exactly one line** and must **never** expose sensitive fields.

### You must handle

**Log injection** — a single log call must produce exactly one line:

- Newline characters in message or values (`\n`, `\r\n`, `%0a`) must be stripped or replaced with a space  
- Tab characters must be replaced with a space  
- A crafted message must not be able to forge a second log entry

**Sensitive field masking** — if a context key matches any of: `password`, `passwd`, `token`, `secret`, `api_key`, `authorization`, `credit_card` (case-insensitive), the value must be replaced with `[REDACTED]`

**Level validation** — only `DEBUG`, `INFO`, `WARN`, `ERROR` are valid levels

### Examples

```
format_log("INFO", "User logged in", {"user": "alice", "ip": "1.2.3.4"})
→ '[INFO] User logged in user=alice ip=1.2.3.4'

format_log("INFO", "Login attempt", {"password": "hunter2"})
→ '[INFO] Login attempt password=[REDACTED]'

format_log("ERROR", "Failed\nINFO] Fake injected log", {})
→ '[ERROR] Failed INFO] Fake injected log'   # newline stripped, still one line

format_log("INFO", "Auth", {"Authorization": "Bearer eyJ..."})
→ '[INFO] Auth Authorization=[REDACTED]'

format_log("TRACE", "msg", {})
→ ERROR: invalid log level
```

### Constraints

- `len(message) <= 1000`  
- `len(context) <= 50`  
- Output is always a single line (assert `\n` not in output)

