import os
import urllib.parse
from pathlib import Path


def resolve_path(base_dir: str, filename: str) -> str:
    """
    Resolve a user-supplied filename against base_dir.
    Raises ValueError if the resolved path escapes base_dir for any reason.

    Security model
    --------------
    This function validates the path *at the time of the check* (TOCTOU caveat
    below).  Do not cache the returned string — call resolve_path again if you
    need to re-open the file later.

    TOCTOU (time-of-check / time-of-use) notice
    --------------------------------------------
    A race exists between this check and the caller's open():

        1. resolve_path("/base", "tmp/file") → "/base/tmp/file"  ✓
        2. Attacker replaces /base/tmp/ with a symlink → /etc/
        3. Caller opens "/base/tmp/file" → actually opens /etc/file  ✗

    To close the race, use open_safe() below instead of resolve_path() +
    open().  open_safe() opens the file atomically with O_NOFOLLOW and
    re-verifies the descriptor's real path.

    Remaining gap: intermediate directory symlinks require kernel-level defence
    (openat(2) + O_NOFOLLOW at every component, or Linux's O_PATH + openat
    chaining).  For most application servers, open_safe() is sufficient; a
    hardened system would use a capability-based fd-walking approach or a
    dedicated sandboxing layer (seccomp, pledge, etc.).
    """
    # Reject null bytes immediately (before any decoding)
    if "\x00" in filename:
        raise ValueError("ERROR: null byte in filename")

    # Reject absolute paths
    if os.path.isabs(filename):
        raise ValueError("ERROR: absolute path rejected")

    # URL-decode to catch %2e%2e%2f and similar tricks (including overlong encodings)
    decoded = urllib.parse.unquote(filename)

    # Decode again to handle double-encoding (%252e%252e%252f)
    decoded = urllib.parse.unquote(decoded)

    # Reject null bytes again after decoding
    if "\x00" in decoded:
        raise ValueError("ERROR: null byte in filename")

    # Reject absolute paths after decoding
    if os.path.isabs(decoded):
        raise ValueError("ERROR: absolute path rejected")

    # Join and resolve all symlinks / . / .. references
    candidate = Path(os.path.realpath(os.path.join(base_dir, decoded)))
    real_base = Path(os.path.realpath(base_dir))

    # Use Path.relative_to() for the containment check.
    #
    # WHY NOT startswith()?
    # str.startswith("/var/www/files") matches "/var/www/files_evil/x" even
    # with a trailing-sep guard, because path separator handling is subtle.
    # Path.relative_to() operates on parsed path *components*, not raw bytes,
    # so "/var/www/files_evil".relative_to("/var/www/files") raises ValueError
    # regardless of separators or trailing slashes.
    try:
        candidate.relative_to(real_base)
    except ValueError:
        raise ValueError("ERROR: traversal detected")

    return str(candidate)


def open_safe(base_dir: str, filename: str, flags: int = os.O_RDONLY):
    """
    Validate and open a file atomically, narrowing the TOCTOU window.

    Returns an open file descriptor (int).  The caller is responsible for
    closing it (os.close(fd) or wrap with open(fd, ...)).

    Uses O_NOFOLLOW on the final path component so a symlink swap between
    resolve_path's realpath() and this open() is detected and rejected.

    Linux only: after opening, the fd's real path is re-verified via
    /proc/self/fd/{fd} for a belt-and-suspenders check.
    """
    validated = resolve_path(base_dir, filename)

    try:
        fd = os.open(validated, flags | os.O_NOFOLLOW)
    except OSError as e:
        raise ValueError(f"ERROR: could not open file (possible symlink swap): {e}")

    # Belt-and-suspenders: re-read the fd's resolved path and re-check containment.
    # Works on Linux (/proc) and macOS (fcntl F_GETPATH).
    try:
        fd_real = _fd_realpath(fd)
    except OSError:
        os.close(fd)
        raise ValueError("ERROR: could not verify file descriptor path")

    real_base = Path(os.path.realpath(base_dir))
    try:
        Path(fd_real).relative_to(real_base)
    except ValueError:
        os.close(fd)
        raise ValueError("ERROR: traversal detected after open (TOCTOU attempt blocked)")

    return fd


def _fd_realpath(fd: int) -> str:
    """Return the real filesystem path for an open file descriptor."""
    import sys
    if sys.platform == "linux":
        return os.readlink(f"/proc/self/fd/{fd}")
    elif sys.platform == "darwin":
        import fcntl
        # macOS F_GETPATH (50) fills a 1024-byte buffer with the resolved path.
        # fcntl.fcntl copies an immutable bytes arg, passes it to the syscall,
        # and returns the populated bytes result.
        result = fcntl.fcntl(fd, 50, b"\x00" * 1024)
        return result.split(b"\x00", 1)[0].decode()
    else:
        raise OSError("fd realpath not supported on this platform")


if __name__ == "__main__":
    base = "/var/www/files"

    tests = [
        ("report.pdf",           None),
        ("../etc/passwd",        "traversal"),
        ("%2e%2e/secret",        "traversal"),
        ("/etc/shadow",          "absolute"),
        ("notes\x00.pdf",        "null byte"),
        ("sub/../../etc/hosts",  "traversal"),
        ("%2e%2e%2fetc%2fpasswd","traversal"),
    ]

    for filename, expect_err in tests:
        try:
            result = resolve_path(base, filename)
            status = "OK" if expect_err is None else "UNEXPECTED OK"
            print(f"[{status}] resolve({filename!r}) → {result}")
        except ValueError as e:
            status = "OK" if expect_err else "UNEXPECTED ERR"
            print(f"[{status}] resolve({filename!r}) → {e}")
