import pytest
from format_log import format_log


class TestHappyPath:
    def test_info_with_context(self):
        result = format_log("INFO", "User logged in", {"user": "alice", "ip": "1.2.3.4"})
        assert result == "[INFO] User logged in user=alice ip=1.2.3.4"

    def test_error_no_context(self):
        result = format_log("ERROR", "Something broke", {})
        assert result == "[ERROR] Something broke"

    def test_debug_level(self):
        result = format_log("DEBUG", "Connecting", {"host": "db01"})
        assert result.startswith("[DEBUG]")

    def test_warn_level(self):
        result = format_log("WARN", "Disk low", {"pct": "90"})
        assert result.startswith("[WARN]")

    def test_output_is_single_line(self):
        result = format_log("INFO", "msg", {"k": "v"})
        assert "\n" not in result
        assert "\r" not in result


class TestSensitiveMasking:
    def test_password_masked(self):
        result = format_log("INFO", "Login", {"password": "hunter2"})
        assert "hunter2" not in result
        assert "[REDACTED]" in result

    def test_token_masked(self):
        result = format_log("INFO", "Auth", {"token": "abc123"})
        assert "abc123" not in result
        assert "[REDACTED]" in result

    def test_secret_masked(self):
        result = format_log("INFO", "Config", {"secret": "s3cr3t"})
        assert "[REDACTED]" in result

    def test_api_key_masked(self):
        result = format_log("INFO", "Request", {"api_key": "key-xyz"})
        assert "key-xyz" not in result
        assert "[REDACTED]" in result

    def test_authorization_masked(self):
        result = format_log("INFO", "Auth", {"Authorization": "Bearer eyJ..."})
        assert "eyJ" not in result
        assert "[REDACTED]" in result

    def test_credit_card_masked(self):
        result = format_log("INFO", "Payment", {"credit_card": "4111111111111111"})
        assert "4111" not in result
        assert "[REDACTED]" in result

    def test_case_insensitive_masking(self):
        result = format_log("INFO", "msg", {"PASSWORD": "secret123"})
        assert "secret123" not in result

    def test_non_sensitive_key_not_masked(self):
        result = format_log("INFO", "msg", {"username": "alice"})
        assert "alice" in result

    def test_passwd_masked(self):
        result = format_log("INFO", "msg", {"passwd": "abc"})
        assert "[REDACTED]" in result


class TestLogInjection:
    def test_newline_in_message_stripped(self):
        result = format_log("ERROR", "Failed\nINFO] Fake injected log", {})
        assert "\n" not in result
        assert "Failed" in result

    def test_carriage_return_stripped(self):
        result = format_log("INFO", "line1\r\nline2", {})
        assert "\r" not in result
        assert "\n" not in result

    def test_tab_in_message_replaced(self):
        result = format_log("INFO", "col1\tcol2", {})
        assert "\t" not in result

    def test_newline_in_context_value_stripped(self):
        result = format_log("INFO", "msg", {"key": "val\nINFO] injected"})
        assert "\n" not in result

    def test_percent0a_literal_allowed(self):
        # %0a as literal text (not decoded) should pass through safely
        result = format_log("INFO", "url?x=%0a", {})
        assert "\n" not in result


class TestLevelValidation:
    def test_invalid_level_trace(self):
        with pytest.raises(ValueError, match="level"):
            format_log("TRACE", "msg", {})

    def test_invalid_level_critical(self):
        with pytest.raises(ValueError, match="level"):
            format_log("CRITICAL", "msg", {})

    def test_invalid_level_lowercase(self):
        with pytest.raises(ValueError, match="level"):
            format_log("info", "msg", {})

    def test_invalid_level_empty(self):
        with pytest.raises(ValueError, match="level"):
            format_log("", "msg", {})
