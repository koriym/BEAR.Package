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

### AI-Only Detectable (Requires Context Understanding)

| File | Vulnerability | Why AI Needed |
|------|---------------|---------------|
| Admin.php | IDOR | Requires understanding authorization context |
| Admin.php | Mass Assignment | Requires understanding business logic (role field) |
| Admin.php | Race Condition | Requires understanding concurrent execution |
| Auth.php | Timing Attack | Requires understanding cryptographic timing |

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
