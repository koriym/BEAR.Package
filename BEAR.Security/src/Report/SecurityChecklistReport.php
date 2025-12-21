<?php

declare(strict_types=1);

namespace BEAR\Security\Report;

use BEAR\Security\ScanResult;
use BEAR\Security\VulnerabilityInterface;

use function count;
use function date;
use function htmlspecialchars;
use function implode;
use function json_encode;
use function round;
use function sprintf;
use function str_contains;

use const ENT_QUOTES;
use const JSON_PRETTY_PRINT;
use const JSON_UNESCAPED_UNICODE;
use const PHP_EOL;

/**
 * Generates security checklist reports based on OWASP Top 10
 */
final class SecurityChecklistReport
{
    /** @var array<string, array{name: string, cwe: string[], status: string, findings: list<string>}> */
    private array $checklist;
    private TemplateRenderer $renderer;

    public function __construct(?TemplateRenderer $renderer = null)
    {
        $this->checklist = $this->initializeChecklist();
        $this->renderer = $renderer ?? new TemplateRenderer();
    }

    /**
     * Generate report from scan result
     *
     * @param string $format 'text', 'json', or 'html'
     */
    public function generate(ScanResult $result, string $format = 'text'): string
    {
        $this->analyzeVulnerabilities($result);

        return match ($format) {
            'json' => $this->toJson(),
            'html' => $this->toHtml(),
            default => $this->toText(),
        };
    }

    private function analyzeVulnerabilities(ScanResult $result): void
    {
        foreach ($result->getVulnerabilities() as $vulnerability) {
            $this->categorizeVulnerability($vulnerability);
        }
    }

    private function categorizeVulnerability(VulnerabilityInterface $vulnerability): void
    {
        $type = $vulnerability->getType();

        // Map vulnerability types to OWASP categories
        // Note: More specific types should be checked first to avoid prefix matching issues
        $mappings = [
            'A10' => ['RFI', 'SSRF', 'RFI_INCLUDE_USER_INPUT', 'RFI_REQUIRE_USER_INPUT', 'RFI_FILE_GET_CONTENTS_URL', 'DAST_RFI'],
            'A01' => ['PATH_TRAVERSAL', 'DAST_PATH_TRAVERSAL'],
            'A02' => ['WEAK_HASH', 'INSECURE_RANDOM', 'HARDCODED_PASSWORD', 'HARDCODED_API_KEY', 'HARDCODED_DB_PASSWORD', 'HARDCODED_PRIVATE_KEY', 'HARDCODED_AWS_KEY', 'DEPRECATED_MCRYPT', 'WEAK_CIPHER', 'ECB_MODE', 'INSECURE_PASSWORD_COMPARE'],
            'A03' => ['SQL_INJECTION', 'XSS', 'COMMAND_INJECTION', 'DAST_SQL_INJECTION', 'DAST_XSS', 'DAST_COMMAND_INJECTION', 'DANGEROUS_EVAL', 'DANGEROUS_EXEC'],
            'A05' => ['MISSING_SECURITY_HEADER', 'INSECURE_HEADER', 'INFO_DISCLOSURE_HEADER', 'CSRF_COOKIE_NO_SAMESITE'],
            'A06' => ['VULNERABLE_DEPENDENCY', 'OUTDATED_COMPONENT'],
            'A07' => ['SESSION_FIXATION', 'CSRF', 'CSRF_FORM_NO_TOKEN', 'CSRF_NO_TOKEN_CHECK', 'DAST_CSRF'],
            'A08' => ['INSECURE_UNSERIALIZE', 'INSECURE_YAML', 'WAKEUP_DANGEROUS', 'DESTRUCT_DANGEROUS', 'PHAR_WRAPPER'],
        ];

        foreach ($mappings as $category => $types) {
            foreach ($types as $mappedType) {
                if ($type !== $mappedType && ! str_contains($type, $mappedType)) {
                    continue;
                }

                $finding = sprintf(
                    '%s: %s (%s)',
                    $type,
                    $vulnerability->getDescription(),
                    $vulnerability->getFile(),
                );
                $this->checklist[$category] = [
                    'name' => $this->checklist[$category]['name'],
                    'cwe' => $this->checklist[$category]['cwe'],
                    'status' => 'FAIL',
                    'findings' => [...$this->checklist[$category]['findings'], $finding],
                ];

                return;
            }
        }
    }

    private function toText(): string
    {
        $lines = [];
        $lines[] = '╔════════════════════════════════════════════════════════════════════════╗';
        $lines[] = '║                   OWASP Top 10 Security Report                         ║';
        $lines[] = '╠════════════════════════════════════════════════════════════════════════╣';
        $lines[] = sprintf('║  Generated: %s                                       ║', date('Y-m-d H:i:s'));
        $lines[] = '╚════════════════════════════════════════════════════════════════════════╝';
        $lines[] = '';

        $passed = 0;
        $failed = 0;
        $notApplicable = 0;

        foreach ($this->checklist as $id => $item) {
            $statusIcon = match ($item['status']) {
                'PASS' => '[✓]',
                'FAIL' => '[✗]',
                default => '[−]',
            };

            $statusColor = match ($item['status']) {
                'PASS' => 'PASS',
                'FAIL' => 'FAIL',
                default => 'N/A ',
            };

            $lines[] = sprintf(
                '%s %s %s: %s',
                $statusIcon,
                $statusColor,
                $id,
                $item['name'],
            );

            if ($item['status'] === 'PASS') {
                $passed++;
            } elseif ($item['status'] === 'FAIL') {
                $failed++;
                foreach ($item['findings'] as $finding) {
                    $lines[] = sprintf('         └─ %s', $finding);
                }
            } else {
                $notApplicable++;
            }

            $lines[] = sprintf('         CWE: %s', implode(', ', $item['cwe']));
            $lines[] = '';
        }

        $total = count($this->checklist);
        $score = $total > 0 ? round((float) $passed / $total * 100) : 0;

        $lines[] = '════════════════════════════════════════════════════════════════════════';
        $lines[] = sprintf('Summary: %d/%d checks passed (%.0f%%)', $passed, $total, $score);
        $lines[] = sprintf('  Passed: %d  |  Failed: %d  |  N/A: %d', $passed, $failed, $notApplicable);
        $lines[] = '════════════════════════════════════════════════════════════════════════';

        return implode(PHP_EOL, $lines);
    }

    private function toJson(): string
    {
        $passed = 0;
        $failed = 0;

        foreach ($this->checklist as $item) {
            if ($item['status'] === 'PASS') {
                $passed++;
            } elseif ($item['status'] === 'FAIL') {
                $failed++;
            }
        }

        $data = [
            'report' => 'OWASP Top 10 Security Checklist',
            'generated' => date('c'),
            'summary' => [
                'total' => count($this->checklist),
                'passed' => $passed,
                'failed' => $failed,
                'score' => count($this->checklist) > 0
                    ? round((float) $passed / count($this->checklist) * 100)
                    : 0,
            ],
            'checklist' => $this->checklist,
        ];

        return (string) json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    }

    private function toHtml(): string
    {
        $passed = 0;
        $failed = 0;

        foreach ($this->checklist as $item) {
            if ($item['status'] === 'PASS') {
                $passed++;
            } elseif ($item['status'] === 'FAIL') {
                $failed++;
            }
        }

        $total = count($this->checklist);
        $score = $total > 0 ? round((float) $passed / $total * 100) : 0;

        $items = '';
        foreach ($this->checklist as $id => $item) {
            $statusClass = match ($item['status']) {
                'PASS' => 'pass',
                'FAIL' => 'fail',
                default => 'na',
            };
            $statusIcon = match ($item['status']) {
                'PASS' => '✓',
                'FAIL' => '✗',
                default => '−',
            };

            $findingsHtml = '';
            if ($item['status'] === 'FAIL' && count($item['findings']) > 0) {
                $findingsHtml = '<div class="findings">';
                foreach ($item['findings'] as $finding) {
                    $escapedFinding = htmlspecialchars($finding, ENT_QUOTES, 'UTF-8');
                    $findingsHtml .= "<div class=\"finding\">• {$escapedFinding}</div>";
                }

                $findingsHtml .= '</div>';
            }

            $statusLabel = match ($item['status']) {
                'PASS' => 'Passed',
                'FAIL' => 'Failed',
                default => 'N/A',
            };

            $items .= $this->renderer->render('checklist-item.html', [
                'statusClass' => $statusClass,
                'statusIcon' => $statusIcon,
                'statusLabel' => $statusLabel,
                'id' => $id,
                'name' => $item['name'],
                'cwe' => implode(', ', $item['cwe']),
                'findings' => $findingsHtml,
            ]);
        }

        return $this->renderer->render('checklist.html', [
            'score' => (string) $score,
            'passed' => (string) $passed,
            'failed' => (string) $failed,
            'items' => $items,
            'generated' => date('Y-m-d H:i:s'),
        ]);
    }

    /** @return array<string, array{name: string, cwe: string[], status: string, findings: list<string>}> */
    private function initializeChecklist(): array
    {
        return [
            'A01' => [
                'name' => 'Broken Access Control',
                'cwe' => ['CWE-22', 'CWE-23', 'CWE-35', 'CWE-59'],
                'status' => 'PASS',
                'findings' => [],
            ],
            'A02' => [
                'name' => 'Cryptographic Failures',
                'cwe' => ['CWE-259', 'CWE-327', 'CWE-331'],
                'status' => 'PASS',
                'findings' => [],
            ],
            'A03' => [
                'name' => 'Injection',
                'cwe' => ['CWE-79', 'CWE-89', 'CWE-78'],
                'status' => 'PASS',
                'findings' => [],
            ],
            'A04' => [
                'name' => 'Insecure Design',
                'cwe' => ['CWE-209', 'CWE-256', 'CWE-501'],
                'status' => 'PASS',
                'findings' => [],
            ],
            'A05' => [
                'name' => 'Security Misconfiguration',
                'cwe' => ['CWE-16', 'CWE-611'],
                'status' => 'PASS',
                'findings' => [],
            ],
            'A06' => [
                'name' => 'Vulnerable and Outdated Components',
                'cwe' => ['CWE-1035', 'CWE-1104'],
                'status' => 'PASS',
                'findings' => [],
            ],
            'A07' => [
                'name' => 'Identification and Authentication Failures',
                'cwe' => ['CWE-287', 'CWE-384'],
                'status' => 'PASS',
                'findings' => [],
            ],
            'A08' => [
                'name' => 'Software and Data Integrity Failures',
                'cwe' => ['CWE-502', 'CWE-829'],
                'status' => 'PASS',
                'findings' => [],
            ],
            'A09' => [
                'name' => 'Security Logging and Monitoring Failures',
                'cwe' => ['CWE-778'],
                'status' => 'PASS',
                'findings' => [],
            ],
            'A10' => [
                'name' => 'Server-Side Request Forgery (SSRF)',
                'cwe' => ['CWE-918'],
                'status' => 'PASS',
                'findings' => [],
            ],
        ];
    }
}
