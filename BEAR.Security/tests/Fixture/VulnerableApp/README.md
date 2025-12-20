# VulnerableApp - Security Testing Fixture

**DO NOT use this code in production!**

This is an intentionally vulnerable BEAR.Sunday application for testing BEAR.Security detectors.

## Vulnerabilities by Detection Method

### SAST Detectable (Pattern-based)

| File | Vulnerability | OWASP | Detector |
|------|---------------|-------|----------|
| User.php | SQL Injection | A03 | SqlInjectionDetector |
| Search.php | XSS | A03 | XssDetector |
| Search.php | Command Injection | A03 | CommandInjectionDetector |
| File.php | Path Traversal | A01 | PathTraversalDetector |
| File.php | SSRF/RFI | A10 | RemoteFileInclusionDetector |
| Auth.php | Weak Hash (MD5) | A02 | CryptographicFailuresDetector |
| Auth.php | Hardcoded Secrets | A02 | CryptographicFailuresDetector |
| Auth.php | Insecure Deserialization | A08 | InsecureDeserializationDetector |
| Auth.php | Session Fixation | A07 | SessionSecurityDetector |
| config/prod.php | Hardcoded Credentials | A02 | CryptographicFailuresDetector |
| Misc.php | Open Redirect | A01 | Pattern + Context |
| Misc.php | Log Injection | - | AI-Only |
| Misc.php | XXE | A05 | XxeDetector |
| Misc.php | ReDoS | - | AI-Only |
| Misc.php | Header Injection | A03 | HeaderInjectionDetector |
| Misc.php | Weak Random | A02 | CryptographicFailuresDetector |

### AI-Only Detectable (Requires Context Understanding)

| File | Vulnerability | Why AI Needed |
|------|---------------|---------------|
| Admin.php | IDOR | Requires understanding authorization context |
| Admin.php | Mass Assignment | Requires understanding business logic (role field) |
| Admin.php | Race Condition | Requires understanding concurrent execution |
| Auth.php | Timing Attack | Requires understanding cryptographic timing |
| Misc.php | Log Injection | Requires understanding log context |
| Misc.php | ReDoS | Requires understanding regex complexity |
| Misc.php | Open Redirect | Requires understanding URL validation |

## Expected Scan Results

Running `vendor/bin/bear.security-scan tests/Fixture/VulnerableApp/src` should detect:

- 2+ SQL Injection
- 1+ XSS
- 1+ Command Injection
- 1+ Path Traversal
- 1+ RFI/SSRF
- 3+ Hardcoded Secrets
- 1+ Weak Hash
- 1+ Insecure Deserialization
- 1+ Session Issue

AI Auditor should additionally detect:
- IDOR vulnerability
- Mass assignment vulnerability
- Race condition (TOCTOU)
- Timing attack vulnerability

## False Positives (SafeButSuspicious.php)

These should NOT be flagged:

| Code Pattern | Why It's Safe |
|--------------|---------------|
| `$userInput` in prepared statement | Parameter binding prevents injection |
| `exec()` on PDO | PDO::exec, not shell_exec |
| `shell_exec()` with whitelist | Input validated against allowed list |
| `serialize()` on internal data | Not deserializing user input |
| `file_get_contents()` with basename | Path traversal prevented |
| `md5()` for cache key | Non-security hash purpose |
| Placeholder secrets | Values like `YOUR_API_KEY_HERE` |

AI should recognize context and avoid false positives.
