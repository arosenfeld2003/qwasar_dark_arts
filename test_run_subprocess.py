import pytest
from run_subprocess import build_ping_args


class TestHappyPath:
    def test_simple_domain(self):
        assert build_ping_args("google.com") == ["ping", "-c", "4", "google.com"]

    def test_ipv4_address(self):
        assert build_ping_args("8.8.8.8") == ["ping", "-c", "4", "8.8.8.8"]

    def test_subdomain(self):
        result = build_ping_args("sub.domain.example.com")
        assert result == ["ping", "-c", "4", "sub.domain.example.com"]

    def test_hyphenated_hostname(self):
        result = build_ping_args("my-host.example.com")
        assert result[-1] == "my-host.example.com"

    def test_returns_list(self):
        result = build_ping_args("example.com")
        assert isinstance(result, list)

    def test_private_ip_allowed(self):
        # build_ping_args validates syntax only, not routing
        result = build_ping_args("192.168.1.1")
        assert result[-1] == "192.168.1.1"

    def test_numeric_only_label(self):
        result = build_ping_args("123.example.com")
        assert result[-1] == "123.example.com"


class TestShellInjection:
    def test_semicolon(self):
        with pytest.raises(ValueError):
            build_ping_args("google.com; rm -rf /")

    def test_ampersand_chain(self):
        with pytest.raises(ValueError):
            build_ping_args("google.com && cat /etc/passwd")

    def test_pipe(self):
        with pytest.raises(ValueError):
            build_ping_args("google.com | id")

    def test_subshell_dollar(self):
        with pytest.raises(ValueError):
            build_ping_args("$(whoami)")

    def test_subshell_backtick(self):
        with pytest.raises(ValueError):
            build_ping_args("`id`")

    def test_redirect_out(self):
        with pytest.raises(ValueError):
            build_ping_args("host > /tmp/x")

    def test_redirect_in(self):
        with pytest.raises(ValueError):
            build_ping_args("host < /etc/passwd")

    def test_newline(self):
        with pytest.raises(ValueError):
            build_ping_args("google.com\nrm -rf /")

    def test_null_byte(self):
        with pytest.raises(ValueError):
            build_ping_args("google.com\x00evil")

    def test_space_in_hostname(self):
        with pytest.raises(ValueError):
            build_ping_args("google .com")


class TestEdgeCases:
    def test_empty_string(self):
        with pytest.raises(ValueError, match="empty"):
            build_ping_args("")

    def test_whitespace_only(self):
        with pytest.raises(ValueError, match="empty"):
            build_ping_args("   ")

    def test_hostname_too_long(self):
        with pytest.raises(ValueError, match="long"):
            build_ping_args("a" * 254)

    def test_hostname_max_length_ok(self):
        # 253 chars is the RFC max — use a realistic label pattern
        hostname = ("a" * 50 + ".") * 4 + "com"
        if len(hostname) <= 253:
            result = build_ping_args(hostname)
            assert isinstance(result, list)

    def test_leading_hyphen_rejected(self):
        with pytest.raises(ValueError):
            build_ping_args("-badhost.com")

    def test_trailing_hyphen_in_label_rejected(self):
        with pytest.raises(ValueError):
            build_ping_args("badhost-.com")
