import os
import sys
import tempfile
import pytest
from solve_file_path import resolve_path, open_safe

BASE = "/var/www/files"


class TestHappyPath:
    def test_simple_filename(self):
        result = resolve_path(BASE, "report.pdf")
        assert result.endswith("/var/www/files/report.pdf")

    def test_nested_file(self):
        result = resolve_path(BASE, "subdir/notes.txt")
        assert result.endswith("/var/www/files/subdir/notes.txt")

    def test_dot_in_filename(self):
        result = resolve_path(BASE, "my.file.tar.gz")
        assert result.endswith("/var/www/files/my.file.tar.gz")


class TestTraversal:
    def test_double_dot(self):
        with pytest.raises(ValueError, match="traversal"):
            resolve_path(BASE, "../etc/passwd")

    def test_nested_traversal(self):
        with pytest.raises(ValueError, match="traversal"):
            resolve_path(BASE, "sub/../../etc/hosts")

    def test_deep_escape(self):
        with pytest.raises(ValueError, match="traversal"):
            resolve_path(BASE, "a/b/../../../etc/shadow")

    def test_url_encoded_dotdot_slash(self):
        with pytest.raises(ValueError, match="traversal"):
            resolve_path(BASE, "%2e%2e/secret")

    def test_url_encoded_full_traversal(self):
        with pytest.raises(ValueError, match="traversal"):
            resolve_path(BASE, "%2e%2e%2fetc%2fpasswd")

    def test_double_encoded_traversal(self):
        with pytest.raises(ValueError, match="traversal"):
            resolve_path(BASE, "%252e%252e%252fetc%252fpasswd")

    def test_mixed_encoding(self):
        with pytest.raises(ValueError, match="traversal"):
            resolve_path(BASE, "..%2fetc/passwd")


class TestAbsolutePaths:
    def test_absolute_path(self):
        with pytest.raises(ValueError, match="absolute"):
            resolve_path(BASE, "/etc/passwd")

    def test_absolute_path_shadow(self):
        with pytest.raises(ValueError, match="absolute"):
            resolve_path(BASE, "/etc/shadow")

    def test_absolute_after_decode(self):
        with pytest.raises(ValueError, match="absolute|traversal"):
            resolve_path(BASE, "%2fetc%2fpasswd")


class TestNullBytes:
    def test_null_byte_in_filename(self):
        with pytest.raises(ValueError, match="null byte"):
            resolve_path(BASE, "notes\x00.pdf")

    def test_null_byte_at_start(self):
        with pytest.raises(ValueError, match="null byte"):
            resolve_path(BASE, "\x00evil")

    def test_null_byte_at_end(self):
        with pytest.raises(ValueError, match="null byte"):
            resolve_path(BASE, "file.pdf\x00")


class TestPrefixConfusion:
    """
    Regression tests for the prefix-check bug.

    The naive fix — startswith(base + "/") — can still be bypassed in edge
    cases involving path-separator normalisation.  Path.relative_to() operates
    on parsed components, not raw bytes, and is the correct primitive.
    """

    def test_sibling_dir_same_prefix(self):
        # /var/www/files_evil shares the string prefix "/var/www/files"
        # but is NOT inside /var/www/files.
        # We can't test via resolve_path() directly (the directory doesn't
        # exist, so realpath won't canonicalise it the way a real FS would),
        # so we verify the Path.relative_to() semantics here directly.
        from pathlib import Path
        base = Path("/var/www/files")
        evil = Path("/var/www/files_evil/secret.txt")

        # String startswith would wrongly pass without the sep guard
        assert str(evil).startswith(str(base))          # ← the bug

        # Path.relative_to() correctly raises
        with pytest.raises(ValueError):
            evil.relative_to(base)

    def test_sibling_dir_blocked_by_resolve_path(self):
        # Create a real temporary directory structure so realpath resolves.
        with tempfile.TemporaryDirectory() as tmpdir:
            base_dir = os.path.join(tmpdir, "files")
            evil_dir = os.path.join(tmpdir, "files_evil")
            os.makedirs(base_dir)
            os.makedirs(evil_dir)

            secret = os.path.join(evil_dir, "secret.txt")
            with open(secret, "w") as f:
                f.write("secret")

            # A traversal that lands in the sibling must be blocked
            with pytest.raises(ValueError, match="traversal"):
                resolve_path(base_dir, "../files_evil/secret.txt")

    def test_base_dir_itself_allowed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base_dir = os.path.join(tmpdir, "files")
            os.makedirs(base_dir)
            # A file directly in base_dir should be allowed
            target = os.path.join(base_dir, "ok.txt")
            with open(target, "w") as f:
                f.write("ok")
            result = resolve_path(base_dir, "ok.txt")
            # realpath resolves macOS /var → /private/var symlink
            assert result == os.path.realpath(target)


class TestTOCTOU:
    """
    Tests for the TOCTOU (time-of-check / time-of-use) mitigation in open_safe().

    The race: after resolve_path() validates a path, an attacker swaps a
    directory for a symlink before the caller opens the file.  open_safe()
    uses O_NOFOLLOW + fd re-verification to detect this on the final component.
    """

    def test_open_safe_valid_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "hello.txt")
            with open(target, "w") as f:
                f.write("hello")

            fd = open_safe(tmpdir, "hello.txt")
            try:
                content = os.read(fd, 100)
                assert content == b"hello"
            finally:
                os.close(fd)

    def test_open_safe_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(ValueError, match="traversal"):
                open_safe(tmpdir, "../etc/passwd")

    @pytest.mark.skipif(sys.platform not in ("linux", "darwin"),
                        reason="O_NOFOLLOW symlink test requires Linux or macOS")
    def test_open_safe_blocks_final_component_symlink(self):
        """
        Simulates the TOCTOU swap: the file is a symlink to something outside
        the base.  open_safe() must reject it via O_NOFOLLOW.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            base_dir = os.path.join(tmpdir, "serve")
            os.makedirs(base_dir)

            # Create a real file outside the base
            outside = os.path.join(tmpdir, "secret.txt")
            with open(outside, "w") as f:
                f.write("SECRET")

            # Place a symlink inside the base pointing outside
            link = os.path.join(base_dir, "evil.txt")
            os.symlink(outside, link)

            with pytest.raises(ValueError):
                open_safe(base_dir, "evil.txt")
