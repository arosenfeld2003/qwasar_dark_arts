import pytest
from validate_url import validate_url


class TestHappyPath:
    def test_https_public_domain(self):
        result = validate_url("https://google.com")
        assert result == "https://google.com"

    def test_http_public_domain(self):
        # May fail in sandboxed envs with no DNS — skip if unresolvable
        pytest.importorskip("socket")
        try:
            result = validate_url("http://example.com")
            assert result == "http://example.com"
        except ValueError as e:
            if "resolve" in str(e):
                pytest.skip("DNS unavailable in this environment")
            raise

    def test_returns_url_unchanged(self):
        url = "https://google.com"
        assert validate_url(url) == url


class TestBlockedSchemes:
    def test_file_scheme(self):
        with pytest.raises(ValueError, match="scheme"):
            validate_url("file:///etc/passwd")

    def test_gopher_scheme(self):
        with pytest.raises(ValueError, match="scheme"):
            validate_url("gopher://internal-service:6379/_FLUSHALL")

    def test_ftp_scheme(self):
        with pytest.raises(ValueError, match="scheme"):
            validate_url("ftp://example.com/file")

    def test_dict_scheme(self):
        with pytest.raises(ValueError, match="scheme"):
            validate_url("dict://localhost:11211/stat")

    def test_no_scheme(self):
        with pytest.raises(ValueError):
            validate_url("//example.com/path")


class TestPrivateRanges:
    def test_loopback_localhost(self):
        with pytest.raises(ValueError):
            validate_url("http://localhost/admin")

    def test_loopback_127_0_0_1(self):
        with pytest.raises(ValueError):
            validate_url("http://127.0.0.1/")

    def test_link_local_aws_metadata(self):
        with pytest.raises(ValueError):
            validate_url("http://169.254.169.254/latest/meta-data/")

    def test_private_10_range(self):
        with pytest.raises(ValueError):
            validate_url("http://10.0.0.1/")

    def test_private_172_range(self):
        with pytest.raises(ValueError):
            validate_url("http://172.16.0.1/")

    def test_private_192_168_range(self):
        with pytest.raises(ValueError):
            validate_url("http://192.168.1.1/")


class TestBypassTricks:
    def test_hex_ip(self):
        with pytest.raises(ValueError):
            validate_url("http://0x7f000001/")

    def test_decimal_ip_loopback(self):
        with pytest.raises(ValueError):
            validate_url("http://2130706433/")

    def test_short_loopback(self):
        with pytest.raises(ValueError):
            validate_url("http://127.1/")

    def test_zero_host(self):
        with pytest.raises(ValueError):
            validate_url("http://0/")


class TestEdgeCases:
    def test_url_too_long(self):
        with pytest.raises(ValueError, match="long"):
            validate_url("https://example.com/" + "a" * 2048)

    def test_missing_hostname(self):
        with pytest.raises(ValueError):
            validate_url("https:///path")
