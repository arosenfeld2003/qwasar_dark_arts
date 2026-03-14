import re

_VALID_LEVELS = {"DEBUG", "INFO", "WARN", "ERROR"}

_SENSITIVE_KEYS = {
    "password", "passwd", "token", "secret",
    "api_key", "authorization", "credit_card",
}

_NEWLINE_RE = re.compile(r'[\n\r\t]')


def _sanitize(text: str) -> str:
    """Replace newlines and tabs with a single space."""
    return _NEWLINE_RE.sub(" ", str(text))


def format_log(level: str, message: str, context: dict) -> str:
    """
    Produce a single-line log entry: [LEVEL] message key=value ...
    - level must be one of DEBUG, INFO, WARN, ERROR
    - newlines/tabs stripped from message and values
    - sensitive keys masked with [REDACTED]
    """
    if level not in _VALID_LEVELS:
        raise ValueError(f"ERROR: invalid log level: {level!r}")

    clean_message = _sanitize(message)

    parts = [f"[{level}] {clean_message}"]

    for key, val in context.items():
        clean_key = _sanitize(str(key))
        if key.lower() in _SENSITIVE_KEYS:
            clean_val = "[REDACTED]"
        else:
            clean_val = _sanitize(val)
        parts.append(f"{clean_key}={clean_val}")

    output = " ".join(parts)
    assert "\n" not in output, "BUG: newline leaked into log output"
    return output


if __name__ == "__main__":
    tests = [
        ("INFO",  "User logged in", {"user": "alice", "ip": "1.2.3.4"},       None),
        ("INFO",  "Login attempt",  {"password": "hunter2"},                   None),
        ("ERROR", "Failed\nINFO] Fake injected log", {},                       None),
        ("INFO",  "Auth",           {"Authorization": "Bearer eyJ..."},        None),
        ("TRACE", "msg",            {},                                         "invalid level"),
        ("WARN",  "Test\r\nInject", {"token": "abc", "user": "bob"},           None),
        ("DEBUG", "x" * 1000,      {},                                         None),
    ]

    for level, msg, ctx, expect_err in tests:
        try:
            result = format_log(level, msg, ctx)
            status = "OK" if expect_err is None else "UNEXPECTED OK"
            print(f"[{status}] format_log({level!r}, {msg[:30]!r}...) → {result!r}")
        except ValueError as e:
            status = "OK" if expect_err else "UNEXPECTED ERR"
            print(f"[{status}] format_log({level!r}, ...) → {e}")
