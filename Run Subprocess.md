## Safe Subprocess Argument Builder 

You are implementing a network diagnostic tool. Users provide a hostname to ping. Implement `build_ping_args(hostname: str) -> list[str]` that returns a safe argument list for `subprocess.run()` (or `execvp` in C).

The returned list must be passable directly to `subprocess.run(args, shell=False)` — **never** as a shell string.

### You must handle

- Shell metacharacters: `; | & $ > < \`   `( ) { } [ ]`  
- Newlines and null bytes  
- Command chaining: `"google.com; rm -rf /"`, `"google.com && cat /etc/passwd"`  
- Subshell injection: `"$(whoami)"`, ``"`id`"``  
- Empty or whitespace-only hostname  
- Hostnames exceeding valid length (max 253 chars per RFC)  
- IP addresses are valid; reject anything that is not a valid hostname or IP

### Examples

```
build_ping_args("google.com")
→ ["ping", "-c", "4", "google.com"]   ✓

build_ping_args("8.8.8.8")
→ ["ping", "-c", "4", "8.8.8.8"]     ✓

build_ping_args("google.com; rm -rf /")
→ ERROR: invalid hostname

build_ping_args("$(cat /etc/passwd)")
→ ERROR: invalid hostname

build_ping_args("")
→ ERROR: empty hostname

build_ping_args("a" * 254)
→ ERROR: hostname too long
```

### Constraints

- Valid hostname chars: `[a-zA-Z0-9.\-]` only  
- Must return a list, never a string  
- Do not use `shell=True` anywhere in your solution

