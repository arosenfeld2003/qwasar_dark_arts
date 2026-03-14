import re

# Valid hostname/IP: letters, digits, hyphens, dots only; max 253 chars
_HOSTNAME_RE = re.compile(r'^[a-zA-Z0-9.\-]+$')

# Each label in a hostname must be 1-63 chars, start/end with alphanumeric
_LABEL_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$')


def _is_valid_ipv4(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        if not (0 <= int(p) <= 255):
            return False
    return True


def _is_valid_hostname(s: str) -> bool:
    """Validate as a DNS hostname per RFC 1123."""
    labels = s.rstrip(".").split(".")
    if not labels:
        return False
    for label in labels:
        if not _LABEL_RE.match(label):
            return False
    return True


def build_ping_args(hostname: str) -> list[str]:
    """
    Validate hostname and return safe argument list for subprocess.run(shell=False).
    Raises ValueError on any invalid or potentially dangerous input.
    """
    if not hostname or not hostname.strip():
        raise ValueError("ERROR: empty hostname")

    if len(hostname) > 253:
        raise ValueError("ERROR: hostname too long")

    # Reject anything that isn't purely alphanumeric, dot, or hyphen
    if not _HOSTNAME_RE.match(hostname):
        raise ValueError("ERROR: invalid hostname")

    # Must be either a valid IPv4 address or a valid DNS hostname
    if not (_is_valid_ipv4(hostname) or _is_valid_hostname(hostname)):
        raise ValueError("ERROR: invalid hostname")

    return ["ping", "-c", "4", hostname]


if __name__ == "__main__":
    tests = [
        ("google.com",              None),
        ("8.8.8.8",                 None),
        ("sub.domain.example.com",  None),
        ("google.com; rm -rf /",   "invalid"),
        ("$(cat /etc/passwd)",     "invalid"),
        ("",                        "empty"),
        ("a" * 254,                 "too long"),
        ("google.com && id",        "invalid"),
        ("host`id`",                "invalid"),
        ("192.168.1.1",             None),
        ("-bad-host",               "invalid"),
        ("good-host.com",           None),
    ]

    for hostname, expect_err in tests:
        try:
            result = build_ping_args(hostname)
            status = "OK" if expect_err is None else "UNEXPECTED OK"
            print(f"[{status}] build_ping_args({hostname[:40]!r}) → {result}")
        except ValueError as e:
            status = "OK" if expect_err else "UNEXPECTED ERR"
            print(f"[{status}] build_ping_args({hostname[:40]!r}) → {e}")
