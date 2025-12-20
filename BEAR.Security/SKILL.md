# BEAR.Security Skill

Security scanner for BEAR.Sunday applications with OWASP Top 10 compliance.

## Overview

BEAR.Security provides comprehensive security analysis for BEAR.Sunday applications:
- **SAST**: Static Application Security Testing (pattern-based)
- **DAST**: Dynamic Application Security Testing (HTTP-based)
- **Psalm Taint**: Data flow tracking (via Psalm integration)
- **Composer Audit**: Dependency vulnerability detection

## OWASP Top 10 Coverage (100%)

| ID | Category | Detection |
|----|----------|-----------|
| A01 | Broken Access Control | PathTraversalDetector |
| A02 | Cryptographic Failures | CryptographicFailuresDetector |
| A03 | Injection | SqlInjection, XSS, CommandInjection |
| A04 | Insecure Design | BEAR.Sunday ROA (by design) |
| A05 | Security Misconfiguration | SecurityHeadersAnalyzer |
| A06 | Vulnerable Components | ComposerAuditScanner |
| A07 | Auth Failures | SessionSecurityDetector, CsrfDetector |
| A08 | Integrity Failures | InsecureDeserializationDetector |
| A09 | Logging Failures | PSR-3 Logger via DI (by design) |
| A10 | SSRF | RemoteFileInclusionDetector |

## Detectors

### SAST Detectors (10)

1. **SqlInjectionDetector** - SQL injection via user input
2. **XssDetector** - Cross-site scripting
3. **CommandInjectionDetector** - Shell command injection
4. **PathTraversalDetector** - Directory traversal attacks
5. **RemoteFileInclusionDetector** - RFI/SSRF vulnerabilities
6. **CsrfDetector** - Cross-site request forgery
7. **CryptographicFailuresDetector** - Weak hash, hardcoded secrets
8. **InsecureDeserializationDetector** - Unsafe unserialize()
9. **DangerousFunctionDetector** - eval(), exec(), system()
10. **SessionSecurityDetector** - Session fixation, insecure cookies

### DAST Components

- **DastScanner** - HTTP-based vulnerability testing
- **SecurityHeadersAnalyzer** - HTTP security headers check
- **ResponseAnalyzer** - Response analysis for vulnerabilities
- **Payloads** - SQL, XSS, Command, Path, CSRF, RFI

## Output Formats

```bash
# Console (default)
vendor/bin/bear.security-scan src

# JSON (CI/CD)
vendor/bin/bear.security-scan src --format=json

# SARIF (GitHub Security)
vendor/bin/bear.security-scan src --format=sarif

# OWASP Checklist
vendor/bin/bear.security-scan src --format=checklist
vendor/bin/bear.security-scan src --format=checklist-html
vendor/bin/bear.security-scan src --format=checklist-json
```

## Architecture

```
BEAR\Security
├── Scanner                    # Main entry point
├── Detector/                  # Pattern-based detectors
│   └── AbstractDetector       # Base class with regex patterns
├── Dast/                      # Dynamic testing
│   ├── DastScanner
│   ├── Analyzer/
│   └── Payload/
├── Analyzer/
│   └── ComposerAuditScanner   # Dependency check
├── Output/                    # Formatters
│   ├── ConsoleOutput
│   ├── JsonOutput
│   └── SarifOutput
├── Report/
│   └── SecurityChecklistReport # OWASP Top 10 report
├── ScanResult                 # Results container
└── Vulnerability              # Issue entity
```

## Custom Detector Pattern

```php
use BEAR\Security\Detector\AbstractDetector;

class CustomDetector extends AbstractDetector
{
    protected array $patterns = [
        'VULN_TYPE' => [
            'pattern' => '/regex_pattern/i',
            'severity' => 'HIGH',           // CRITICAL, HIGH, MEDIUM, LOW
            'description' => 'What was found',
            'recommendation' => 'How to fix',
        ],
    ];
}
```

## Severity Levels

- **CRITICAL**: Remote code execution, SQL injection with data exposure
- **HIGH**: XSS, command injection, path traversal
- **MEDIUM**: CSRF, session issues, weak cryptography
- **LOW**: Information disclosure, minor issues

## CI/CD Integration

### GitHub Actions with SARIF

```yaml
- name: Security Scan
  run: vendor/bin/bear.security-scan src --format=sarif > results.sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## BEAR.Sunday Advantages

BEAR.Sunday framework provides security by design:

1. **ROA (Resource Oriented Architecture)**: Clean separation, no global state
2. **Dependency Injection**: No hardcoded dependencies
3. **PSR-3 Logger**: Proper logging via DI
4. **Immutable Resources**: Predictable behavior
5. **Defined Routes**: No need for auto-crawling

## Comparison with VADDY

| Aspect | VADDY | BEAR.Security |
|--------|-------|---------------|
| Type | Commercial SaaS | OSS (MIT) |
| SAST | - | ✓ |
| DAST | ✓ | ✓ |
| Psalm Taint | - | ✓ |
| Auto Crawling | ✓ | N/A (routes defined) |
| OWASP Top 10 | Partial | 100% |
| Cost | Monthly | Free |

**Conclusion**: For BEAR.Sunday, BEAR.Security + Psalm Taint is sufficient.

## AI-Powered Analysis (Future)

### What AI Can Do That Traditional Tools Cannot

1. **Context Understanding**
   - Understand variable purpose from naming and usage
   - Recognize sanitization even with custom functions
   - Detect intent mismatches (code does X but comment says Y)

2. **Cross-File Analysis**
   - Track data flow across multiple files without AST
   - Understand architectural patterns
   - Detect inconsistent security practices

3. **Business Logic Vulnerabilities**
   - Detect authorization bypasses
   - Find race conditions in workflows
   - Identify insecure direct object references (IDOR)

4. **Fix Generation**
   - Suggest specific code fixes
   - Explain why the fix works
   - Provide multiple solution options

5. **False Positive Reduction**
   - Understand context to filter false positives
   - Recognize safe patterns (e.g., admin-only code)
   - Explain reasoning for each finding

### Implementation Options

| Option | Cost | Privacy | Speed |
|--------|------|---------|-------|
| Claude API | ~$0.01-0.05/file | Cloud | Slow |
| Ollama (14B+) | Free | Local | Medium |
| Hybrid | Low | Mixed | Fast+Deep |

### Recommended Approach

```
Daily CI: BEAR.Security + Psalm Taint (free, fast)
Release: + AI analysis (deep, thorough)
```

## Requirements

- PHP 8.1+
- BEAR.Sunday application (recommended)
- Psalm (for taint analysis)
