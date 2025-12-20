<?php

declare(strict_types=1);

namespace BEAR\SecurityScanner;

use BEAR\SecurityScanner\Report\SecurityChecklistReport;
use PHPUnit\Framework\TestCase;

use function json_decode;

class SecurityChecklistReportTest extends TestCase
{
    public function testGenerateTextReportWithNoVulnerabilities(): void
    {
        $result = new ScanResult();
        $report = new SecurityChecklistReport();

        $output = $report->generate($result, 'text');

        $this->assertStringContainsString('OWASP Top 10 Security Checklist Report', $output);
        $this->assertStringContainsString('[✓] PASS A01', $output);
        $this->assertStringContainsString('[✓] PASS A02', $output);
        $this->assertStringContainsString('[✓] PASS A03', $output);
        $this->assertStringContainsString('[✓] PASS A04', $output);
    }

    public function testGenerateTextReportWithVulnerabilities(): void
    {
        $result = new ScanResult();
        $result->addVulnerability(new Vulnerability(
            'SQL_INJECTION',
            VulnerabilityInterface::SEVERITY_CRITICAL,
            '/app/src/test.php',
            10,
            'SQL Injection detected',
            '$query = "SELECT * FROM users WHERE id=" . $_GET["id"]',
            'Use prepared statements',
        ));

        $report = new SecurityChecklistReport();
        $output = $report->generate($result, 'text');

        $this->assertStringContainsString('[✗] FAIL A03', $output);
        $this->assertStringContainsString('SQL_INJECTION', $output);
    }

    public function testGenerateJsonReport(): void
    {
        $result = new ScanResult();
        $result->addVulnerability(new Vulnerability(
            'XSS',
            VulnerabilityInterface::SEVERITY_HIGH,
            '/app/src/test.php',
            20,
            'XSS detected',
            'echo $_GET["name"]',
            'Escape output',
        ));

        $report = new SecurityChecklistReport();
        $output = $report->generate($result, 'json');

        $data = json_decode($output, true);
        $this->assertIsArray($data);

        $this->assertSame('OWASP Top 10 Security Checklist', $data['report']);
        $this->assertArrayHasKey('summary', $data);
        $this->assertArrayHasKey('checklist', $data);

        $checklist = $data['checklist'];
        $this->assertIsArray($checklist);
        $this->assertSame('FAIL', $checklist['A03']['status']);
    }

    public function testGenerateHtmlReport(): void
    {
        $result = new ScanResult();
        $report = new SecurityChecklistReport();

        $output = $report->generate($result, 'html');

        $this->assertStringContainsString('<!DOCTYPE html>', $output);
        $this->assertStringContainsString('OWASP Top 10 Security Checklist Report', $output);
        $this->assertStringContainsString('class="check-item', $output);
    }

    public function testPathTraversalMapsToA01(): void
    {
        $result = new ScanResult();
        $result->addVulnerability(new Vulnerability(
            'PATH_TRAVERSAL',
            VulnerabilityInterface::SEVERITY_HIGH,
            '/app/src/file.php',
            15,
            'Path traversal detected',
            'include($_GET["page"])',
            'Validate file paths',
        ));

        $report = new SecurityChecklistReport();
        $output = $report->generate($result, 'json');

        $data = json_decode($output, true);
        $this->assertIsArray($data);

        $checklist = $data['checklist'];
        $this->assertIsArray($checklist);
        $this->assertSame('FAIL', $checklist['A01']['status']);
    }

    public function testCsrfMapsToA07(): void
    {
        $result = new ScanResult();
        $result->addVulnerability(new Vulnerability(
            'CSRF_FORM_NO_TOKEN',
            VulnerabilityInterface::SEVERITY_HIGH,
            '/app/src/form.php',
            25,
            'CSRF token missing',
            '<form method="post">',
            'Add CSRF token',
        ));

        $report = new SecurityChecklistReport();
        $output = $report->generate($result, 'json');

        $data = json_decode($output, true);
        $this->assertIsArray($data);

        $checklist = $data['checklist'];
        $this->assertIsArray($checklist);
        $this->assertSame('FAIL', $checklist['A07']['status']);
    }

    public function testSsrfMapsToA10(): void
    {
        $result = new ScanResult();
        $result->addVulnerability(new Vulnerability(
            'RFI_FILE_GET_CONTENTS_URL',
            VulnerabilityInterface::SEVERITY_CRITICAL,
            '/app/src/api.php',
            30,
            'SSRF detected',
            'file_get_contents($_GET["url"])',
            'Validate URLs',
        ));

        $report = new SecurityChecklistReport();
        $output = $report->generate($result, 'json');

        $data = json_decode($output, true);
        $this->assertIsArray($data);

        $checklist = $data['checklist'];
        $this->assertIsArray($checklist);
        $this->assertSame('FAIL', $checklist['A10']['status']);
    }

    public function testSummaryCalculation(): void
    {
        $result = new ScanResult();
        $report = new SecurityChecklistReport();

        $output = $report->generate($result, 'json');
        $data = json_decode($output, true);
        $this->assertIsArray($data);

        $summary = $data['summary'];
        $this->assertIsArray($summary);

        // All 10 PASS by default (BEAR.Sunday framework provides secure design)
        $this->assertSame(10, $summary['total']);
        $this->assertSame(10, $summary['passed']);
        $this->assertSame(0, $summary['failed']);
        $this->assertEquals(100, $summary['score']);
    }
}
