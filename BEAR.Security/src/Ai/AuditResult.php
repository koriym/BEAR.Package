<?php

declare(strict_types=1);

namespace BEAR\Security\Ai;

use BEAR\Security\VulnerabilityInterface;

/**
 * Result of AI-powered security audit
 */
final class AuditResult
{
    /**
     * @param list<VulnerabilityInterface> $vulnerabilities Found vulnerabilities
     * @param TokenTracker                 $tokenTracker    Token usage statistics
     * @param array<string, string>        $filesAnalyzed   File path => analysis summary
     * @param list<string>                 $filesSkipped    Files that were skipped
     */
    public function __construct(
        public readonly array $vulnerabilities,
        public readonly TokenTracker $tokenTracker,
        public readonly array $filesAnalyzed = [],
        public readonly array $filesSkipped = [],
    ) {
    }

    /**
     * Get total vulnerabilities count
     */
    public function getVulnerabilityCount(): int
    {
        return count($this->vulnerabilities);
    }

    /**
     * Get vulnerabilities by severity
     *
     * @return array<string, list<VulnerabilityInterface>>
     */
    public function getVulnerabilitiesBySeverity(): array
    {
        $grouped = [
            'CRITICAL' => [],
            'HIGH' => [],
            'MEDIUM' => [],
            'LOW' => [],
        ];

        foreach ($this->vulnerabilities as $vuln) {
            $severity = $vuln->getSeverity();
            if (isset($grouped[$severity])) {
                $grouped[$severity][] = $vuln;
            }
        }

        return $grouped;
    }

    /**
     * Get count of files analyzed
     */
    public function getFilesAnalyzedCount(): int
    {
        return count($this->filesAnalyzed);
    }

    /**
     * Get token usage summary
     */
    public function getTokenSummary(): string
    {
        return $this->tokenTracker->getSummary();
    }
}
