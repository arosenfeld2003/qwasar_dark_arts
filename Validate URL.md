## Outbound URL Validator

Implement `validate_url(url: str) -> str` that returns the URL unchanged **only if** it is safe to fetch. This function is called before every outbound HTTP request your server makes on behalf of a user.

If the URL is unsafe for **any reason**, raise/return an error.

### You must block

**Private/internal network ranges:**

- `127.0.0.0/8` (loopback)  
- `10.0.0.0/8`  
- `172.16.0.0/12`  
- `192.168.0.0/16`  
- `169.254.0.0/16` (link-local — AWS/GCP metadata endpoint lives here)  
- `::1` (IPv6 loopback)  
- `fd00::/8` (IPv6 ULA)

**Dangerous schemes:**

- `file://`, `gopher://`, `ftp://`, `dict://` — only `http` and `https` are allowed

**Bypass tricks:**

- `http://localhost/secret`  
- `http://0/` (0 resolves to 127.0.0.1 on many systems)  
- `http://0x7f000001/` (hex IP)  
- `http://2130706433/` (decimal IP for 127.0.0.1)  
- `http://127.1/` (short-form loopback)  
- DNS rebinding is out of scope, but note it in your comments

### Examples

```
validate_url("https://api.example.com/data")   → "https://api.example.com/data"  ✓
validate_url("https://google.com")             → "https://google.com"            ✓

validate_url("http://169.254.169.254/latest/meta-data/")  → ERROR: private IP range
validate_url("http://localhost/admin")                    → ERROR: loopback address
validate_url("file:///etc/passwd")                        → ERROR: scheme not allowed
validate_url("http://0x7f000001/")                        → ERROR: private IP range
validate_url("http://2130706433/")                        → ERROR: private IP range
validate_url("gopher://internal-service:6379/_FLUSHALL") → ERROR: scheme not allowed
```

### Constraints

- Must resolve the hostname to an IP **before** checking (use `socket.getaddrinfo`)  
- Validate **after** DNS resolution, not just on the raw string  
- `len(url) <= 2048`

