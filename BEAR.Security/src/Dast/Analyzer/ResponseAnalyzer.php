<?php

declare(strict_types=1);

namespace BEAR\Security\Dast\Analyzer;

use BEAR\Security\Dast\Payload\PayloadInterface;
use BEAR\Security\Vulnerability;
use BEAR\Security\VulnerabilityInterface;

use function preg_match;
use function preg_replace;
use function sprintf;
use function strlen;
use function strtoupper;
use function substr;

/**
 * Analyzes HTTP responses for security vulnerabilities
 */
final class ResponseAnalyzer
{
    /**
     * Analyze response for vulnerabilities based on payload
     */
    public function analyze(
        PayloadInterface $payload,
        string $responseBody,
        int $responseCode,
        string $url,
        string $usedPayload,
    ): VulnerabilityInterface|null {
        // Check for success patterns in response
        foreach ($payload->getSuccessPatterns() as $pattern) {
            if (preg_match($pattern, $responseBody)) {
                return new Vulnerability(
                    sprintf('DAST_%s', $this->sanitizeTypeName($payload->getName())),
                    $payload->getSeverity(),
                    $url,
                    0, // Line number not applicable for DAST
                    sprintf(
                        '%s - Payload: %s',
                        $payload->getDescription(),
                        $this->truncatePayload($usedPayload),
                    ),
                    sprintf('Response matched pattern: %s', $pattern),
                    $payload->getRecommendation(),
                );
            }
        }

        // Check for generic error indicators that might reveal vulnerabilities
        $genericVulnerability = $this->checkGenericIndicators($responseBody, $responseCode, $url, $usedPayload);
        if ($genericVulnerability !== null) {
            return $genericVulnerability;
        }

        return null;
    }

    /**
     * Check for generic vulnerability indicators
     */
    private function checkGenericIndicators(
        string $responseBody,
        int $responseCode,
        string $url,
        string $payload,
    ): VulnerabilityInterface|null {
        // Stack trace exposure
        if (preg_match('/Stack trace:|Traceback \(most recent|at .+\(.+:\d+\)/i', $responseBody)) {
            return new Vulnerability(
                'DAST_STACK_TRACE_EXPOSURE',
                VulnerabilityInterface::SEVERITY_MEDIUM,
                $url,
                0,
                'Stack trace exposed in error response - may reveal sensitive information',
                sprintf('Triggered by payload: %s', $this->truncatePayload($payload)),
                'Disable detailed error messages in production. Use custom error pages.',
            );
        }

        // Database connection string exposure
        if (preg_match('/mysql:host=|pgsql:host=|mongodb:\/\/|redis:\/\//i', $responseBody)) {
            return new Vulnerability(
                'DAST_CONNECTION_STRING_EXPOSURE',
                VulnerabilityInterface::SEVERITY_HIGH,
                $url,
                0,
                'Database connection string exposed in response',
                sprintf('Triggered by payload: %s', $this->truncatePayload($payload)),
                'Never expose connection strings. Use environment variables and proper error handling.',
            );
        }

        // File path disclosure
        if (preg_match('/\/var\/www\/|\/home\/\w+\/|C:\\\\(?:Users|Windows|Program Files)/i', $responseBody)) {
            return new Vulnerability(
                'DAST_PATH_DISCLOSURE',
                VulnerabilityInterface::SEVERITY_LOW,
                $url,
                0,
                'Server file path disclosed in response',
                sprintf('Triggered by payload: %s', $this->truncatePayload($payload)),
                'Avoid exposing absolute paths in error messages.',
            );
        }

        // 500 Internal Server Error (might indicate injection success)
        if ($responseCode === 500 && preg_match('/error|exception|fatal/i', $responseBody)) {
            return new Vulnerability(
                'DAST_SERVER_ERROR',
                VulnerabilityInterface::SEVERITY_MEDIUM,
                $url,
                0,
                'Server error triggered by malicious input - may indicate vulnerability',
                sprintf('Payload: %s caused HTTP 500', $this->truncatePayload($payload)),
                'Investigate why this input causes server errors. Ensure proper input validation.',
            );
        }

        return null;
    }

    /**
     * Sanitize payload type name for use as vulnerability type
     */
    private function sanitizeTypeName(string $name): string
    {
        return strtoupper(preg_replace('/[^A-Za-z0-9]+/', '_', $name) ?? $name);
    }

    /**
     * Truncate payload for display
     */
    private function truncatePayload(string $payload, int $maxLength = 50): string
    {
        if (strlen($payload) <= $maxLength) {
            return $payload;
        }

        return substr($payload, 0, $maxLength) . '...';
    }
}
