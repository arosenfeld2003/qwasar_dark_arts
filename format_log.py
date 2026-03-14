import re
import unicodedata

_VALID_LEVELS = {"DEBUG", "INFO", "WARN", "ERROR"}

_SENSITIVE_KEYS = frozenset({
    # Original
    "password", "passwd", "token", "secret",
    "api_key", "authorization", "credit_card",
    # Auth & tokens
    "access_token", "refresh_token", "auth", "auth_token",
    "bearer", "client_secret", "webhook_secret",
    # Session
    "session", "session_id", "sid",
    # MFA / OTP
    "otp", "totp", "mfa_code",
    # PII
    "ssn", "social_security", "dob", "date_of_birth", "pin",
    # Payment
    "cvv", "cvc", "account_number", "routing_number",
    # Crypto / private keys
    "private_key", "private", "encryption_key", "ssh_key",
})

# Cyrillic and Greek Unicode codepoints that visually resemble ASCII letters
# appearing in _SENSITIVE_KEYS words.  Applied after NFKC normalization to
# defeat homoglyph attacks that NFKC alone cannot resolve.
_CONFUSABLE_MAP: dict[str, str] = {
    # Cyrillic
    "\u0430": "a",  # а  → a
    "\u0441": "c",  # с  → c
    "\u0501": "d",  # ԁ  → d
    "\u0435": "e",  # е  → e
    "\u0456": "i",  # і  → i  (Ukrainian)
    "\u04CF": "l",  # ӏ  → l
    "\u043E": "o",  # о  → o
    "\u0440": "p",  # р  → p
    "\u0455": "s",  # ѕ  → s
    "\u0442": "t",  # т  → t
    "\u0443": "u",  # у  → u
    "\u0432": "v",  # в  → v
    # Greek
    "\u03B1": "a",  # α  → a (alpha)
    "\u03BF": "o",  # ο  → o (omicron)
    "\u03C1": "p",  # ρ  → p (rho)
    "\u03B5": "e",  # ε  → e (epsilon)
    "\u03C5": "u",  # υ  → u (upsilon)
}

_NEWLINE_RE = re.compile(r"[\n\r\t]")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _build_inline_re(keys: frozenset[str]) -> re.Pattern[str]:
    """Build a regex matching inline ``key=value`` / ``key: value`` secrets."""
    # Longest keys first so "access_token" beats "token" in alternation.
    alts = "|".join(re.escape(k) for k in sorted(keys, key=len, reverse=True))
    return re.compile(rf"(?:{alts})\s*[=:]\s*\S.*", re.IGNORECASE)


_INLINE_SECRET_RE = _build_inline_re(_SENSITIVE_KEYS)


def _apply_confusables(s: str) -> str:
    return "".join(_CONFUSABLE_MAP.get(c, c) for c in s)


def _normalize_key(key: str) -> str:
    """
    Return a canonical form of *key* used only for sensitive-key matching
    (never for display).

    Steps:
    1. NFKC normalization — collapses fullwidth/compatibility variants
       (e.g. fullwidth ｔｏｋｅｎ → token).
    2. Confusable-character substitution — maps Cyrillic/Greek lookalikes to
       their ASCII equivalents (e.g. Cyrillic р → p).
    3. Strip whitespace — defeats padding attacks (e.g. "password\\t").
    4. Lowercase.
    """
    normalized = unicodedata.normalize("NFKC", str(key))
    normalized = _apply_confusables(normalized)
    return normalized.strip().lower()


def _sanitize(text: str) -> str:
    """
    Return *text* safe for a single-line log entry:
    - ANSI escape sequences removed (prevents terminal spoofing).
    - Null bytes removed (prevents parser truncation).
    - Newlines, carriage returns, and tabs replaced with a space.
    """
    text = _ANSI_RE.sub("", str(text))
    text = text.replace("\x00", "")
    return _NEWLINE_RE.sub(" ", text)


def _is_sensitive_key(normalized_key: str, effective_keys: frozenset[str]) -> bool:
    """
    Return True when *normalized_key* matches any sensitive pattern.

    Exact match handles canonical names; substring match catches composite
    names such as ``db_password`` or ``old_token``.  Over-redaction (e.g.
    ``tokenizer`` contains ``token``) is intentional — a security logger
    should prefer redacting too much over too little.
    """
    if normalized_key in effective_keys:
        return True
    return any(s in normalized_key for s in effective_keys)


def _scrub_inline_secrets(text: str, inline_re: re.Pattern[str]) -> str:
    """Replace inline ``key=value`` / ``key: value`` secrets within *text*."""
    def _replace(m: re.Match) -> str:
        raw = m.group(0)
        sep_idx = raw.index("=") if "=" in raw else raw.index(":")
        return raw[: sep_idx + 1] + "[REDACTED]"

    return inline_re.sub(_replace, text)


def format_log(
    level: str,
    message: str,
    context: dict,
    *,
    extra_sensitive_keys: set[str] | frozenset[str] | None = None,
) -> str:
    """
    Produce a single-line log entry: [LEVEL] message key=value ...

    Security properties
    -------------------
    - *level* must be one of DEBUG, INFO, WARN, ERROR.
    - Newlines, tabs, null bytes, and ANSI escape sequences are stripped from
      the message and all context values.
    - Sensitive context keys are masked with ``[REDACTED]``:
        - Key matching is NFKC-normalized with a confusable-character map,
          defeating fullwidth and Cyrillic/Greek homoglyph bypass attempts.
        - Leading/trailing whitespace is stripped from keys before matching,
          defeating padding attacks (e.g. ``"password\\t"``).
        - Substring matching catches composite names (e.g. ``db_password``,
          ``old_token``).  This may over-redact (e.g. ``tokenizer``); that is
          intentional.
    - Inline ``key=value`` / ``key: value`` patterns inside *values* are also
      masked to catch sensitive data embedded in request bodies or headers.
    - Values containing spaces are double-quoted to prevent structured-log
      parsers from misinterpreting words as extra fields.
    - *extra_sensitive_keys* lets callers supply domain-specific keys to redact
      (e.g. ``{"patient_id", "tax_id"}``).  These are merged with the built-in
      set and participate in both exact and substring matching.
    """
    if level not in _VALID_LEVELS:
        raise ValueError(f"ERROR: invalid log level: {level!r}")

    if extra_sensitive_keys:
        effective_keys: frozenset[str] = _SENSITIVE_KEYS | frozenset(
            k.strip().lower() for k in extra_sensitive_keys
        )
        inline_re = _build_inline_re(effective_keys)
    else:
        effective_keys = _SENSITIVE_KEYS
        inline_re = _INLINE_SECRET_RE

    clean_message = _scrub_inline_secrets(_sanitize(message), inline_re)
    parts = [f"[{level}] {clean_message}"]

    for key, val in context.items():
        clean_key = _sanitize(str(key))
        if _is_sensitive_key(_normalize_key(key), effective_keys):
            clean_val = "[REDACTED]"
        else:
            clean_val = _scrub_inline_secrets(_sanitize(str(val)), inline_re)

        display_val = f'"{clean_val}"' if " " in clean_val else clean_val
        parts.append(f"{clean_key}={display_val}")

    output = " ".join(parts)
    if "\n" in output or "\r" in output:
        raise RuntimeError("BUG: newline leaked into log output")
    return output


if __name__ == "__main__":
    tests = [
        # (level, message, context, extra_sensitive_keys, expect_err)
        ("INFO",  "User logged in",          {"user": "alice", "ip": "1.2.3.4"},                None, None),
        ("INFO",  "Login attempt",           {"password": "hunter2"},                            None, None),
        ("ERROR", "Failed\nINFO] Fake log",  {},                                                 None, None),
        ("INFO",  "Auth",                    {"Authorization": "Bearer eyJ..."},                 None, None),
        ("TRACE", "msg",                     {},                                                 None, "invalid level"),
        ("WARN",  "Test\r\nInject",          {"token": "abc", "user": "bob"},                   None, None),
        # Homoglyph bypass attempt (Cyrillic р and а)
        ("INFO",  "Homoglyph",               {"\u0440\u0430ssword": "leak"},                    None, None),
        # Fullwidth bypass attempt
        ("INFO",  "Fullwidth",               {"\uff54\uff4f\uff4b\uff45\uff4e": "leak"},         None, None),
        # Whitespace-padded key
        ("INFO",  "Padded",                  {"password\t": "leak"},                             None, None),
        # Composite key
        ("INFO",  "Composite",               {"db_password": "leak"},                            None, None),
        # Inline secret in value
        ("INFO",  "Body",                    {"payload": "user=alice password=hunter2"},         None, None),
        # ANSI escape in message
        ("INFO",  "\x1b[31mSpoofed\x1b[0m", {},                                                 None, None),
        # Null byte in value
        ("INFO",  "Null",                    {"key": "ok\x00hidden"},                            None, None),
        # Value with spaces → quoted
        ("INFO",  "Spaced",                  {"msg": "hello world"},                             None, None),
        # User-defined sensitive key
        ("INFO",  "Patient",                 {"patient_id": "12345"},                            {"patient_id"}, None),
        # New sensitive keys
        ("INFO",  "PII",                     {"ssn": "123-45-6789", "cvv": "999"},               None, None),
    ]

    for level, msg, ctx, extra, expect_err in tests:
        try:
            kwargs = {"extra_sensitive_keys": extra} if extra else {}
            result = format_log(level, msg, ctx, **kwargs)
            status = "OK" if expect_err is None else "UNEXPECTED OK"
            print(f"[{status}] format_log({level!r}, {msg[:30]!r}...) → {result!r}")
        except ValueError as e:
            status = "OK" if expect_err else "UNEXPECTED ERR"
            print(f"[{status}] format_log({level!r}, ...) → {e}")
