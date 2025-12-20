<?php

declare(strict_types=1);

namespace BEAR\SecurityScanner\Output;

use BEAR\SecurityScanner\ScanResult;
use BEAR\SecurityScanner\VulnerabilityInterface;

use function array_map;
use function array_values;
use function date;
use function json_encode;
use function preg_replace;
use function strtolower;

use const JSON_PRETTY_PRINT;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;

/**
 * SARIF (Static Analysis Results Interchange Format) output
 *
 * @see https://sarifweb.azurewebsites.net/
 * @see https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
 */
final class SarifOutput implements OutputInterface
{
    private const SARIF_VERSION = '2.1.0';
    private const SCHEMA_URI = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';
    private const TOOL_NAME = 'BEAR.SecurityScanner';
    private const TOOL_URI = 'https://github.com/bearsunday/BEAR.SecurityScanner';

    public function format(ScanResult $result): string
    {
        $sarif = [
            '$schema' => self::SCHEMA_URI,
            'version' => self::SARIF_VERSION,
            'runs' => [
                [
                    'tool' => $this->buildTool(),
                    'results' => $this->buildResults($result),
                    'invocations' => [
                        [
                            'executionSuccessful' => true,
                            'endTimeUtc' => date('c'),
                        ],
                    ],
                ],
            ],
        ];

        $json = json_encode($sarif, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        return $json === false ? '{}' : $json;
    }

    /**
     * Build tool information
     *
     * @return array<string, mixed>
     */
    private function buildTool(): array
    {
        return [
            'driver' => [
                'name' => self::TOOL_NAME,
                'informationUri' => self::TOOL_URI,
                'version' => '1.0.0',
                'rules' => $this->buildRules(),
            ],
        ];
    }

    /**
     * Build rule definitions
     *
     * @return list<array<string, mixed>>
     */
    private function buildRules(): array
    {
        return [
            $this->buildRule('SQL_INJECTION', 'SQL Injection', 'A03', 'CWE-89'),
            $this->buildRule('XSS', 'Cross-Site Scripting', 'A03', 'CWE-79'),
            $this->buildRule('COMMAND_INJECTION', 'Command Injection', 'A03', 'CWE-78'),
            $this->buildRule('PATH_TRAVERSAL', 'Path Traversal', 'A01', 'CWE-22'),
            $this->buildRule('RFI', 'Remote File Inclusion', 'A10', 'CWE-98'),
            $this->buildRule('CSRF', 'Cross-Site Request Forgery', 'A07', 'CWE-352'),
            $this->buildRule('WEAK_HASH', 'Weak Cryptographic Hash', 'A02', 'CWE-328'),
            $this->buildRule('HARDCODED_PASSWORD', 'Hardcoded Password', 'A02', 'CWE-259'),
            $this->buildRule('INSECURE_UNSERIALIZE', 'Insecure Deserialization', 'A08', 'CWE-502'),
            $this->buildRule('DANGEROUS_EVAL', 'Dangerous Function', 'A03', 'CWE-95'),
            $this->buildRule('SESSION_FIXATION', 'Session Fixation', 'A07', 'CWE-384'),
            $this->buildRule('VULNERABLE_DEPENDENCY', 'Vulnerable Dependency', 'A06', 'CWE-1035'),
        ];
    }

    /**
     * Build a single rule definition
     *
     * @return array<string, mixed>
     */
    private function buildRule(string $id, string $name, string $owaspCategory, string $cwe): array
    {
        return [
            'id' => $id,
            'name' => $name,
            'shortDescription' => ['text' => $name],
            'fullDescription' => ['text' => "Detects {$name} vulnerabilities (OWASP {$owaspCategory})"],
            'helpUri' => "https://owasp.org/Top10/A{$owaspCategory}/",
            'properties' => [
                'tags' => ['security', 'owasp-' . strtolower($owaspCategory), $cwe],
            ],
        ];
    }

    /**
     * Build results from vulnerabilities
     *
     * @return list<array<string, mixed>>
     */
    private function buildResults(ScanResult $result): array
    {
        return array_values(array_map(
            fn (VulnerabilityInterface $vuln) => $this->buildResult($vuln),
            $result->getVulnerabilities(),
        ));
    }

    /**
     * Build a single result
     *
     * @return array<string, mixed>
     */
    private function buildResult(VulnerabilityInterface $vulnerability): array
    {
        return [
            'ruleId' => $this->normalizeRuleId($vulnerability->getType()),
            'level' => $this->mapSeverityToLevel($vulnerability->getSeverity()),
            'message' => [
                'text' => $vulnerability->getDescription(),
            ],
            'locations' => [
                [
                    'physicalLocation' => [
                        'artifactLocation' => [
                            'uri' => $vulnerability->getFile(),
                        ],
                        'region' => [
                            'startLine' => $vulnerability->getLine() > 0 ? $vulnerability->getLine() : 1,
                        ],
                    ],
                ],
            ],
            'fixes' => [
                [
                    'description' => [
                        'text' => $vulnerability->getRecommendation(),
                    ],
                ],
            ],
        ];
    }

    /**
     * Normalize rule ID to match defined rules
     */
    private function normalizeRuleId(string $type): string
    {
        // Remove suffixes like _GET, _POST, etc.
        $normalized = (string) preg_replace('/_(?:GET|POST|REQUEST|COOKIE|FILE|VARIABLE|URL|PASSWORD|KEY|DB).*$/i', '', $type);

        return $normalized ?: $type;
    }

    /**
     * Map severity to SARIF level
     */
    private function mapSeverityToLevel(string $severity): string
    {
        return match ($severity) {
            VulnerabilityInterface::SEVERITY_CRITICAL => 'error',
            VulnerabilityInterface::SEVERITY_HIGH => 'error',
            VulnerabilityInterface::SEVERITY_MEDIUM => 'warning',
            VulnerabilityInterface::SEVERITY_LOW => 'note',
            default => 'warning',
        };
    }
}
