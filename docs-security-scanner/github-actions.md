# GitHub Actions Integration

## SARIF Integration (Recommended)

Upload results directly to GitHub Security tab for integrated vulnerability tracking:

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
          composer require --dev bear/security-scanner
          vendor/bin/bear.security-scan src --format=sarif > results.sarif

      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

This displays vulnerabilities in the GitHub Security tab alongside CodeQL findings.

## Quick Start

Add this workflow to your project at `.github/workflows/security.yml`:

```yaml
name: Security

on:
  push:
    branches: [master, main]
  pull_request:

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: shivammathur/setup-php@v2
        with:
          php-version: '8.1'

      - run: composer install --no-interaction

      - name: Security Scan
        run: |
          composer require --dev bear/security-scanner
          vendor/bin/bear.security-scan src --format=checklist
```

## Full Configuration

```yaml
name: Security Scan

on:
  push:
    branches: [master, main, develop]
  pull_request:
  schedule:
    - cron: '0 0 * * 1'  # Weekly on Monday

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: shivammathur/setup-php@v2
        with:
          php-version: '8.1'

      - run: composer install --no-interaction

      - name: Run Security Scanner
        run: |
          composer require --dev bear/security-scanner
          vendor/bin/bear.security-scan src --format=json > report.json
          vendor/bin/bear.security-scan src --format=checklist-html > report.html

      - name: Fail on Critical
        run: |
          CRITICAL=$(jq '[.vulnerabilities[] | select(.severity == "CRITICAL")] | length' report.json)
          if [ "$CRITICAL" -gt 0 ]; then
            echo "::error::Found $CRITICAL critical vulnerabilities"
            exit 1
          fi

      - name: Upload Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-report
          path: |
            report.json
            report.html

  composer-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: shivammathur/setup-php@v2
        with:
          php-version: '8.1'

      - run: composer install --no-interaction

      - name: Composer Audit
        run: composer audit
```

## DAST Integration

For Dynamic Application Security Testing with a running application:

```yaml
jobs:
  dast:
    runs-on: ubuntu-latest
    services:
      app:
        image: your-app-image
        ports:
          - 8080:80

    steps:
      - uses: actions/checkout@v4

      - uses: shivammathur/setup-php@v2
        with:
          php-version: '8.1'

      - run: composer install --no-interaction

      - name: Wait for app
        run: |
          timeout 60 bash -c 'until curl -s http://localhost:8080; do sleep 1; done'

      - name: DAST Scan
        run: |
          composer require --dev bear/security-scanner
          vendor/bin/bear.security-scan --dast http://localhost:8080 --format=json
```

## Severity Threshold

Control which severities cause the workflow to fail:

```yaml
- name: Check Severity
  run: |
    # Fail on CRITICAL only
    CRITICAL=$(jq '[.vulnerabilities[] | select(.severity == "CRITICAL")] | length' report.json)

    # Or fail on HIGH and above
    HIGH=$(jq '[.vulnerabilities[] | select(.severity == "CRITICAL" or .severity == "HIGH")] | length' report.json)

    if [ "$CRITICAL" -gt 0 ]; then
      exit 1
    fi
```

## Pull Request Comments

Add findings as PR comments using actions:

```yaml
- name: Comment PR
  if: github.event_name == 'pull_request' && failure()
  uses: actions/github-script@v7
  with:
    script: |
      const fs = require('fs');
      const report = JSON.parse(fs.readFileSync('report.json', 'utf8'));
      const vulns = report.vulnerabilities;

      if (vulns.length > 0) {
        const body = `## Security Scan Results\n\n` +
          `Found ${vulns.length} vulnerabilities:\n\n` +
          vulns.map(v => `- **${v.severity}**: ${v.type} in ${v.file}:${v.line}`).join('\n');

        github.rest.issues.createComment({
          issue_number: context.issue.number,
          owner: context.repo.owner,
          repo: context.repo.repo,
          body: body
        });
      }
```
