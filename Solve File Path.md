## File Path Resolver

You are building a file server. Users request files by name. Implement `resolve_path(base_dir: str, filename: str) -> str` that returns the absolute path of the file **only if it is strictly inside `base_dir`**.

If the resolved path escapes the base directory for **any reason**, raise/return an error — do **not** attempt to sanitize and retry. Reject and stop.

### You must handle

- `../` traversal sequences (and URL-encoded variants like `%2e%2e%2f`)  
- Null bytes in the filename (`\x00`)  
- Absolute paths passed as filename (`/etc/passwd`)  
- Unicode tricks (`..%c0%af` — overlong slash encoding)  
- Filenames that after resolution point outside base via symlinks (bonus)

### Examples

```
base = "/var/www/files"

resolve("/var/www/files", "report.pdf")         → "/var/www/files/report.pdf"  ✓
resolve("/var/www/files", "../etc/passwd")       → ERROR: traversal detected
resolve("/var/www/files", "%2e%2e/secret")       → ERROR: traversal detected
resolve("/var/www/files", "/etc/shadow")         → ERROR: absolute path rejected
resolve("/var/www/files", "notes\x00.pdf")       → ERROR: null byte in filename
resolve("/var/www/files", "sub/../../etc/hosts") → ERROR: traversal detected
```

### Constraints

- `base_dir` is a trusted, already-validated absolute path  
- `filename` is untrusted user input  
- Your check must happen **after** full resolution, not just string matching on `".."`

