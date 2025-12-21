# BEAR.Security Detection Matrix

## Overview

Documentation of BEAR.Security detection capabilities.

- **SAST**: 14 Detectors
- **DAST**: HTTP-based testing
- **AI Auditor**: Claude API integration
- **Psalm Taint**: Data flow tracking (external)
- **Composer Audit**: Dependency vulnerabilities (external)

---

## OWASP Top 10 (2021) Coverage

| ID | Category | SAST | DAST | AI | Status |
|----|----------|:----:|:----:|:--:|:------:|
| A01 | Broken Access Control | ✓ | ✓ | ✓ | **Covered** |
| A02 | Cryptographic Failures | ✓ | - | ✓ | **Covered** |
| A03 | Injection | ✓ | ✓ | ✓ | **Covered** |
| A04 | Insecure Design | - | - | ✓ | AI-only |
| A05 | Security Misconfiguration | ✓ | ✓ | ✓ | **Covered** |
| A06 | Vulnerable Components | - | - | - | composer audit |
| A07 | Auth Failures | ✓ | ✓ | ✓ | **Covered** |
| A08 | Integrity Failures | ✓ | - | ✓ | **Covered** |
| A09 | Logging Failures | - | - | ✓ | AI-only |
| A10 | SSRF | ✓ | ✓ | ✓ | **Covered** |

---

## SAST Detectors (14)

### Detectable Vulnerabilities

| Detector | CWE | Vulnerability | Pattern Example |
|----------|-----|---------------|-----------------|
| SqlInjectionDetector | CWE-89 | SQL Injection | `query("SELECT * FROM users WHERE id = " . $id)` |
| XssDetector | CWE-79 | Cross-Site Scripting | `echo $_GET['name']` |
| CommandInjectionDetector | CWE-78 | OS Command Injection | `shell_exec('ls ' . $dir)` |
| PathTraversalDetector | CWE-22 | Path Traversal | `file_get_contents('/data/' . $_GET['file'])` |
| RemoteFileInclusionDetector | CWE-98, CWE-918 | RFI/SSRF | `file_get_contents($_POST['url'])` |
| CsrfDetector | CWE-352 | CSRF | Form without token |
| CryptographicFailuresDetector | CWE-327, CWE-259 | Weak crypto, hardcoded secrets | `md5($password)`, `$apiKey = 'sk_live_...'` |
| InsecureDeserializationDetector | CWE-502 | Insecure Deserialization | `unserialize($_POST['data'])` |
| DangerousFunctionDetector | CWE-94 | Dangerous Functions | `eval($code)`, `assert($expr)` |
| SessionSecurityDetector | CWE-384 | Session Fixation | `$_SESSION['user'] = $id` (no regenerate_id) |
| OpenRedirectDetector | CWE-601 | Open Redirect | `header('Location: ' . $_GET['url'])` |
| XxeDetector | CWE-611 | XXE | `simplexml_load_string($_POST['xml'])` |
| HeaderInjectionDetector | CWE-113 | HTTP Header Injection | `header('Set-Cookie: ' . $_GET['v'])` |
| WeakRandomDetector | CWE-330 | Weak Random | `$token = md5(time())` |

---

## AI Auditor Detection

Vulnerabilities requiring context understanding:

| Vulnerability | CWE | Detection Approach |
|---------------|-----|-------------------|
| IDOR | CWE-639 | Missing authorization checks |
| Mass Assignment | CWE-915 | Dynamic field updates with privilege escalation risk |
| Race Condition (TOCTOU) | CWE-367 | Non-atomic check-then-act patterns |
| Timing Attack | CWE-208 | `===` vs `hash_equals()` |
| Business Logic Flaw | CWE-840 | Logic errors in business rules |
| Log Injection | CWE-117 | Unsanitized data in logs |
| ReDoS | CWE-1333 | Regex complexity analysis |

---

## DAST Detection

| Vulnerability | Payload | Detection Method |
|---------------|---------|------------------|
| SQL Injection | `' OR '1'='1`, `1; DROP TABLE` | Error response, delay |
| XSS (Reflected) | `<script>alert(1)</script>` | Reflection check |
| Command Injection | `; ls -la`, `\| cat /etc/passwd` | Response content |
| Path Traversal | `../../../etc/passwd` | File content check |
| CSRF | POST without token | Success check |
| Open Redirect | `//evil.com` | Redirect target |

---

## Out of Scope (Other Tools Recommended)

| Vulnerability Category | Recommended Tool |
|------------------------|------------------|
| Dependency CVE | `composer audit`, Snyk, Dependabot |
| Container Vulnerabilities | Trivy, Grype |
| Infrastructure Config | Checkov, tfsec |
| Network | OpenVAS, Nessus |
| API Spec Violations | OWASP ZAP, Burp Suite |
| Secrets in Git | gitleaks, truffleHog |

---

## CI/CD Security Gate Criteria

### Fail Conditions (Recommended)

| Severity | Threshold | Action |
|----------|-----------|--------|
| CRITICAL | 1+ | Build fail |
| HIGH | 3+ | Build fail |
| MEDIUM | 10+ | Warning |
| LOW | No limit | Info only |

### GitHub Actions Example

```yaml
- name: SAST Scan
  run: vendor/bin/bear.security-scan src --format=sarif > sast.sarif

- name: AI Audit (Release only)
  if: github.event_name == 'release'
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  run: vendor/bin/bear-security-audit src --format=sarif > ai-audit.sarif
```

---

## Comparison: BEAR.Security vs Other Tools

| Feature | BEAR.Security | VADDY | ZAP | PHPStan |
|---------|:-------------:|:-----:|:---:|:-------:|
| SAST (Static Analysis) | ✓ | - | - | ✓ |
| DAST (Dynamic Testing) | ✓ | ✓ | ✓ | - |
| AI Analysis | ✓ | - | - | - |
| Psalm Taint Integration | ✓ | - | - | - |
| OWASP Top 10 100% | ✓ | △ | ✓ | △ |
| SARIF Output | ✓ | - | ✓ | ✓ |
| OSS/Free | ✓ | - | ✓ | ✓ |
| BEAR.Sunday Optimized | ✓ | - | - | - |

---

## False Positive Avoidance Rules

Patterns AI recognizes as safe:

| Pattern | Reason Safe |
|---------|-------------|
| `$pdo->prepare()` + `execute([$var])` | Parameter binding |
| `$pdo->exec()` (DDL) | Not shell_exec |
| `escapeshellarg()` + whitelist | Input validated |
| `basename()` + fixed base path | Path traversal prevented |
| `md5()` for cache key | Non-security purpose |
| `YOUR_API_KEY_HERE` | Placeholder |

---

## Future Enhancements

- [ ] Bedrock Auditor (AWS)
- [ ] Ollama Auditor (Local LLM)
- [ ] GraphQL vulnerability detection
- [ ] WebSocket vulnerability detection
- [ ] Custom rules YAML definition
