# BEAR.Security

Security scanner for BEAR.Sunday applications with OWASP Top 10 compliance.

[![Build Status](https://github.com/bearsunday/BEAR.Security/workflows/CI/badge.svg)](https://github.com/bearsunday/BEAR.Security/actions)

## Features

- **SAST** - Static Application Security Testing (14 detectors)
- **DAST** - Dynamic Application Security Testing
- **AI Auditor** - Context-aware analysis via Claude API
- **OWASP Top 10** - 100% coverage for BEAR.Sunday applications
- **Multiple Output Formats** - Console, JSON, SARIF, HTML
- **GitHub Security Integration** - SARIF output for Security tab

See also: [Detection Matrix](docs/detection-matrix.md) | [Comparison with VADDY](docs/comparison-vaddy.md)

## Installation

```bash
composer require --dev bear/security
```

## Usage

### Basic Scan

```bash
vendor/bin/bear.security-scan src
```

### Output Formats

```bash
# Console output (default)
vendor/bin/bear.security-scan src

# JSON for CI/CD
vendor/bin/bear.security-scan src --format=json > report.json

# SARIF for GitHub Security
vendor/bin/bear.security-scan src --format=sarif > report.sarif

# OWASP Top 10 Checklist
vendor/bin/bear.security-scan src --format=checklist
vendor/bin/bear.security-scan src --format=checklist-html -o report.html
```

### Exclude Patterns

```bash
vendor/bin/bear.security-scan src --exclude='/vendor/' --exclude='/tests/'
```

## OWASP Top 10 Coverage

| Category | Detection |
|----------|-----------|
| A01: Broken Access Control | Path Traversal |
| A02: Cryptographic Failures | Weak Hash, Hardcoded Secrets |
| A03: Injection | SQL, XSS, Command Injection |
| A04: Insecure Design | BEAR.Sunday ROA design |
| A05: Security Misconfiguration | HTTP Security Headers |
| A06: Vulnerable Components | Composer Audit |
| A07: Auth Failures | Session Fixation, CSRF |
| A08: Integrity Failures | Insecure Deserialization |
| A09: Logging Failures | PSR-3 Logger (BEAR DI) |
| A10: SSRF | Remote File Inclusion |

## Detectors

### SAST (14 Detectors)

| Detector | CWE | Severity | Description |
|----------|-----|----------|-------------|
| SqlInjection | CWE-89 | CRITICAL | SQL injection vulnerabilities |
| XSS | CWE-79 | HIGH | Cross-site scripting |
| CommandInjection | CWE-78 | CRITICAL | Shell command injection |
| PathTraversal | CWE-22 | HIGH | Directory traversal attacks |
| RemoteFileInclusion | CWE-918 | CRITICAL | RFI/SSRF vulnerabilities |
| CSRF | CWE-352 | MEDIUM | Cross-site request forgery |
| CryptographicFailures | CWE-327 | HIGH | Weak hash, hardcoded secrets |
| InsecureDeserialization | CWE-502 | CRITICAL | Unsafe unserialize() |
| DangerousFunctions | CWE-94 | HIGH | eval(), exec(), system() |
| SessionSecurity | CWE-384 | MEDIUM | Session fixation |
| OpenRedirect | CWE-601 | HIGH | Unvalidated redirects |
| XXE | CWE-611 | HIGH | XML External Entity |
| HeaderInjection | CWE-113 | HIGH | HTTP header injection |
| WeakRandom | CWE-330 | MEDIUM | Insecure random generation |

### AI Auditor (Context-Aware)

Detects vulnerabilities that require context understanding:

| Vulnerability | CWE | Description |
|---------------|-----|-------------|
| IDOR | CWE-639 | Authorization bypass |
| Mass Assignment | CWE-915 | Privilege escalation |
| Race Condition | CWE-367 | TOCTOU |
| Timing Attack | CWE-208 | Side-channel |
| Business Logic | CWE-840 | Logic flaws |

```bash
# AI Audit (requires ANTHROPIC_API_KEY)
ANTHROPIC_API_KEY=sk-xxx vendor/bin/bear-security-audit src
```

### DAST (Dynamic Analysis)

- SQL Injection payloads
- XSS payloads
- Command Injection payloads
- Path Traversal payloads
- Security Headers analysis

## GitHub Actions Integration

```yaml
name: Security

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - uses: shivammathur/setup-php@v2
        with:
          php-version: '8.1'

      - run: composer install --no-interaction

      - name: Security Scan
        run: |
          composer require --dev bear/security
          vendor/bin/bear.security-scan src --format=sarif > results.sarif

      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Programmatic Usage

```php
use BEAR\Security\Scanner;
use BEAR\Security\Output\JsonOutput;

$scanner = new Scanner();
$result = $scanner->scanDirectory('./src');

// Get vulnerabilities
foreach ($result->getVulnerabilities() as $vuln) {
    echo sprintf(
        "[%s] %s in %s:%d\n",
        $vuln->getSeverity(),
        $vuln->getType(),
        $vuln->getFile(),
        $vuln->getLine()
    );
}

// JSON output
$output = new JsonOutput();
echo $output->format($result);
```

### OWASP Checklist Report

```php
use BEAR\Security\Scanner;
use BEAR\Security\Report\SecurityChecklistReport;

$scanner = new Scanner();
$result = $scanner->scanDirectory('./src');

$report = new SecurityChecklistReport();

// Text report
echo $report->generate($result, 'text');

// JSON report
echo $report->generate($result, 'json');

// HTML report
echo $report->generate($result, 'html');
```

### Custom Detectors

```php
use BEAR\Security\Scanner;
use BEAR\Security\Detector\AbstractDetector;

class CustomDetector extends AbstractDetector
{
    protected array $patterns = [
        'CUSTOM_ISSUE' => [
            'pattern' => '/dangerous_function\s*\(/i',
            'severity' => 'HIGH',
            'description' => 'Dangerous function detected',
            'recommendation' => 'Use safer alternative',
        ],
    ];
}

$scanner = new Scanner();
$scanner->addDetector(new CustomDetector());
```

## Psalm Taint Analysis

This package has Psalm taint analysis enabled. Run separately for data flow analysis:

```bash
vendor/bin/psalm --taint-analysis
```

## Requirements

- PHP 8.1+
- BEAR.Sunday application (recommended)

## Documentation

- [Detection Matrix](docs/detection-matrix.md) - Detection coverage
- [GitHub Actions Integration](docs/github-actions.md)
- [Comparison with VADDY](docs/comparison-vaddy.md)
- [LLM Context](docs/llms.txt) | [Full](docs/llms-full.txt)

## License

MIT License
