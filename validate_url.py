import ipaddress
import socket
import urllib.parse


_ALLOWED_SCHEMES = {"http", "https"}

# Private/reserved ranges to block (SSRF prevention)
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("10.0.0.0/8"),        # private
    ipaddress.ip_network("172.16.0.0/12"),     # private
    ipaddress.ip_network("192.168.0.0/16"),    # private
    ipaddress.ip_network("169.254.0.0/16"),    # link-local (AWS/GCP metadata)
    ipaddress.ip_network("0.0.0.0/8"),         # "this" network (0 → 127.0.0.1)
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 ULA (covers fd00::/8)
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
    ipaddress.ip_network("100.64.0.0/10"),     # CGNAT
]


def _is_blocked_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return True  # unparseable → reject
    for network in _BLOCKED_NETWORKS:
        if ip in network:
            return True
    return False


def validate_url(url: str) -> str:
    """
    Validate url is safe to fetch outbound.
    - Only http/https schemes allowed
    - Hostname resolves to a non-private IP
    - Blocks bypass tricks (hex IPs, decimal IPs, localhost aliases)
    Raises ValueError if unsafe; returns url unchanged if safe.

    NOTE: DNS rebinding (the IP changes between validation and fetch) is out of
    scope for this function. The caller should use short TTL pinning or make the
    validated IP canonical in the request.
    """
    if len(url) > 2048:
        raise ValueError("ERROR: URL too long")

    parsed = urllib.parse.urlparse(url)

    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        raise ValueError(f"ERROR: scheme not allowed: {parsed.scheme!r}")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("ERROR: missing hostname")

    # Resolve hostname to all IPs — this also normalises hex/decimal/short-form IPs
    # because getaddrinfo hands them to the OS resolver.
    try:
        results = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise ValueError(f"ERROR: could not resolve hostname {hostname!r}: {e}")

    for *_, sockaddr in results:
        ip_str = sockaddr[0]
        if _is_blocked_ip(ip_str):
            raise ValueError(f"ERROR: private IP range ({ip_str})")

    return url


if __name__ == "__main__":
    tests = [
        ("https://api.example.com/data",             None),
        ("https://google.com",                       None),
        ("http://169.254.169.254/latest/meta-data/", "private"),
        ("http://localhost/admin",                   "loopback"),
        ("file:///etc/passwd",                       "scheme"),
        ("http://0x7f000001/",                       "private"),
        ("http://2130706433/",                       "private"),
        ("gopher://internal-service:6379/_FLUSHALL", "scheme"),
        ("ftp://example.com/file",                   "scheme"),
        ("http://0/",                                "private"),
        ("http://127.1/",                            "private"),
    ]

    for url, expect_err in tests:
        try:
            result = validate_url(url)
            status = "OK" if expect_err is None else "UNEXPECTED OK"
            print(f"[{status}] validate_url({url!r}) → {result!r}")
        except ValueError as e:
            status = "OK" if expect_err else "UNEXPECTED ERR"
            print(f"[{status}] validate_url({url!r}) → {e}")
        except Exception as e:
            print(f"[EXCEPTION] validate_url({url!r}) → {type(e).__name__}: {e}")
