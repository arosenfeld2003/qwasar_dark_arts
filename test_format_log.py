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

    # --- Extended sensitive key coverage ---

    def test_ssn_masked(self):
        result = format_log("INFO", "PII", {"ssn": "123-45-6789"})
        assert "123-45-6789" not in result
        assert "[REDACTED]" in result

    def test_cvv_masked(self):
        result = format_log("INFO", "Payment", {"cvv": "999"})
        assert "999" not in result
        assert "[REDACTED]" in result

    def test_cvc_masked(self):
        result = format_log("INFO", "Payment", {"cvc": "123"})
        assert "[REDACTED]" in result

    def test_access_token_masked(self):
        result = format_log("INFO", "OAuth", {"access_token": "eyJabc"})
        assert "eyJabc" not in result
        assert "[REDACTED]" in result

    def test_refresh_token_masked(self):
        result = format_log("INFO", "OAuth", {"refresh_token": "tok_refresh"})
        assert "tok_refresh" not in result
        assert "[REDACTED]" in result

    def test_session_id_masked(self):
        result = format_log("INFO", "Session", {"session_id": "sess_abc"})
        assert "sess_abc" not in result
        assert "[REDACTED]" in result

    def test_otp_masked(self):
        result = format_log("INFO", "2FA", {"otp": "123456"})
        assert "123456" not in result
        assert "[REDACTED]" in result

    def test_pin_masked(self):
        result = format_log("INFO", "ATM", {"pin": "1234"})
        assert "1234" not in result
        assert "[REDACTED]" in result

    def test_private_key_masked(self):
        result = format_log("INFO", "TLS", {"private_key": "-----BEGIN RSA"})
        assert "BEGIN RSA" not in result
        assert "[REDACTED]" in result

    def test_client_secret_masked(self):
        result = format_log("INFO", "OAuth", {"client_secret": "cs_abc"})
        assert "cs_abc" not in result
        assert "[REDACTED]" in result


class TestSubstringKeyMasking:
    """Composite key names containing a sensitive word must be redacted."""

    def test_db_password_masked(self):
        result = format_log("INFO", "DB", {"db_password": "hunter2"})
        assert "hunter2" not in result
        assert "[REDACTED]" in result

    def test_old_token_masked(self):
        result = format_log("INFO", "Rotate", {"old_token": "abc"})
        assert "abc" not in result
        assert "[REDACTED]" in result

    def test_user_secret_v2_masked(self):
        result = format_log("INFO", "Config", {"user_secret_v2": "xyz"})
        assert "xyz" not in result
        assert "[REDACTED]" in result

    def test_reset_password_hash_masked(self):
        result = format_log("INFO", "Reset", {"reset_password_hash": "bcrypt"})
        assert "bcrypt" not in result
        assert "[REDACTED]" in result

    def test_non_sensitive_substring_not_over_redacted(self):
        # "host" contains no sensitive word
        result = format_log("INFO", "msg", {"host": "db01"})
        assert "db01" in result


class TestHomoglyphBypass:
    """Unicode lookalike characters must not bypass sensitive-key detection."""

    def test_fullwidth_token_masked(self):
        # ｔｏｋｅｎ (fullwidth) → NFKC → token
        result = format_log("INFO", "Auth", {"\uff54\uff4f\uff4b\uff45\uff4e": "leak"})
        assert "leak" not in result
        assert "[REDACTED]" in result

    def test_fullwidth_password_masked(self):
        # ｐａｓｓｗｏｒｄ
        result = format_log("INFO", "Auth", {"\uff50\uff41\uff53\uff53\uff57\uff4f\uff52\uff44": "leak"})
        assert "leak" not in result
        assert "[REDACTED]" in result

    def test_cyrillic_p_and_a_in_password_masked(self):
        # Cyrillic р (U+0440) and а (U+0430) substituted for p and a
        result = format_log("INFO", "Auth", {"\u0440\u0430ssword": "leak"})
        assert "leak" not in result
        assert "[REDACTED]" in result

    def test_cyrillic_token_masked(self):
        # Cyrillic т (U+0442) substituted for t
        result = format_log("INFO", "Auth", {"\u0442oken": "leak"})
        assert "leak" not in result
        assert "[REDACTED]" in result


class TestWhitespacePaddedKeys:
    """Keys padded with whitespace must not bypass sensitive-key detection."""

    def test_tab_padded_password_masked(self):
        result = format_log("INFO", "Auth", {"password\t": "leak"})
        assert "leak" not in result
        assert "[REDACTED]" in result

    def test_leading_space_password_masked(self):
        result = format_log("INFO", "Auth", {" password": "leak"})
        assert "leak" not in result
        assert "[REDACTED]" in result

    def test_trailing_newline_token_masked(self):
        result = format_log("INFO", "Auth", {"token\n": "leak"})
        assert "leak" not in result
        assert "[REDACTED]" in result


class TestValueLevelScanning:
    """Inline key=value secrets inside context values must be masked."""

    def test_password_in_value_masked(self):
        result = format_log("INFO", "Body", {"payload": "user=alice password=hunter2"})
        assert "hunter2" not in result
        assert "[REDACTED]" in result

    def test_token_in_value_masked(self):
        result = format_log("INFO", "Header", {"raw": "Authorization: Bearer eyJ"})
        assert "eyJ" not in result

    def test_secret_in_value_masked(self):
        result = format_log("INFO", "Cfg", {"data": "secret=myvalue"})
        assert "myvalue" not in result
        assert "[REDACTED]" in result

    def test_safe_value_not_mangled(self):
        result = format_log("INFO", "DB", {"query": "SELECT * FROM users"})
        assert "SELECT * FROM users" in result

    def test_inline_secret_in_message_masked(self):
        result = format_log("INFO", "connecting with password=hunter2 to host", {})
        assert "hunter2" not in result
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
        result = format_log("INFO", "url?x=%0a", {})
        assert "\n" not in result

    def test_ansi_escape_in_message_stripped(self):
        result = format_log("INFO", "\x1b[31mSpoofed\x1b[0m", {})
        assert "\x1b" not in result
        assert "Spoofed" in result

    def test_ansi_escape_in_value_stripped(self):
        result = format_log("INFO", "msg", {"key": "\x1b[2Jvisible"})
        assert "\x1b" not in result

    def test_null_byte_in_value_removed(self):
        result = format_log("INFO", "msg", {"key": "ok\x00hidden"})
        assert "\x00" not in result
        assert "ok" in result

    def test_null_byte_in_message_removed(self):
        result = format_log("INFO", "ok\x00injected", {})
        assert "\x00" not in result

    def test_value_with_spaces_is_quoted(self):
        result = format_log("INFO", "msg", {"note": "hello world"})
        assert 'note="hello world"' in result

    def test_value_without_spaces_not_quoted(self):
        result = format_log("INFO", "msg", {"user": "alice"})
        assert "user=alice" in result
        assert '"alice"' not in result


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


class TestUserDefinedSensitiveKeys:
    def test_extra_key_is_masked(self):
        result = format_log("INFO", "Patient", {"patient_id": "12345"},
                            extra_sensitive_keys={"patient_id"})
        assert "12345" not in result
        assert "[REDACTED]" in result

    def test_extra_key_case_insensitive(self):
        result = format_log("INFO", "Tax", {"TAX_ID": "999"},
                            extra_sensitive_keys={"tax_id"})
        assert "999" not in result

    def test_extra_key_substring_match(self):
        result = format_log("INFO", "DB", {"user_patient_id": "42"},
                            extra_sensitive_keys={"patient_id"})
        assert "42" not in result
        assert "[REDACTED]" in result

    def test_extra_key_does_not_affect_unrelated_keys(self):
        result = format_log("INFO", "msg", {"user": "alice"},
                            extra_sensitive_keys={"patient_id"})
        assert "alice" in result

    def test_builtin_keys_still_masked_with_extras(self):
        result = format_log("INFO", "Auth", {"password": "secret", "patient_id": "42"},
                            extra_sensitive_keys={"patient_id"})
        assert "secret" not in result
        assert "42" not in result

    def test_no_extra_keys_baseline_unchanged(self):
        result = format_log("INFO", "msg", {"user": "alice"})
        assert "alice" in result
