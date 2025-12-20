<?php

declare(strict_types=1);

namespace BEAR\Security\Dast;

use BEAR\Resource\ResourceInterface;
use BEAR\Security\Dast\Analyzer\ResponseAnalyzer;
use BEAR\Security\Dast\Payload\CommandInjectionPayload;
use BEAR\Security\Dast\Payload\PathTraversalPayload;
use BEAR\Security\Dast\Payload\PayloadInterface;
use BEAR\Security\Dast\Payload\SqlInjectionPayload;
use BEAR\Security\Dast\Payload\XssPayload;
use BEAR\Security\VulnerabilityInterface;

use function array_merge;
use function implode;
use function sprintf;
use function strtoupper;
use function urlencode;

/**
 * Trait for adding security testing capabilities to PHPUnit tests
 *
 * Use this trait in your BEAR.Sunday WorkflowTest classes to add security testing.
 *
 * Example:
 * ```php
 * class SecurityWorkflowTest extends WorkflowTest
 * {
 *     use SecurityTest;
 *
 *     public function testIndexNoSqlInjection(): void
 *     {
 *         $this->assertNoSqlInjection('/users?id=%s');
 *     }
 * }
 * ```
 */
trait SecurityTest
{
    protected ResponseAnalyzer $securityAnalyzer;

    /** @var VulnerabilityInterface[] */
    protected array $detectedVulnerabilities = [];

    /**
     * Initialize security testing components
     * Call this in setUp() if not using the initSecurityTesting() method
     */
    protected function initSecurityTesting(): void
    {
        $this->securityAnalyzer = new ResponseAnalyzer();
        $this->detectedVulnerabilities = [];
    }

    /**
     * Assert that the endpoint is not vulnerable to SQL injection
     *
     * @param string $endpointPattern Endpoint with %s placeholder for payload
     */
    protected function assertNoSqlInjection(string $endpointPattern): void
    {
        $this->assertNoVulnerability($endpointPattern, new SqlInjectionPayload());
    }

    /**
     * Assert that the endpoint is not vulnerable to XSS
     *
     * @param string $endpointPattern Endpoint with %s placeholder for payload
     */
    protected function assertNoXss(string $endpointPattern): void
    {
        $this->assertNoVulnerability($endpointPattern, new XssPayload());
    }

    /**
     * Assert that the endpoint is not vulnerable to command injection
     *
     * @param string $endpointPattern Endpoint with %s placeholder for payload
     */
    protected function assertNoCommandInjection(string $endpointPattern): void
    {
        $this->assertNoVulnerability($endpointPattern, new CommandInjectionPayload());
    }

    /**
     * Assert that the endpoint is not vulnerable to path traversal
     *
     * @param string $endpointPattern Endpoint with %s placeholder for payload
     */
    protected function assertNoPathTraversal(string $endpointPattern): void
    {
        $this->assertNoVulnerability($endpointPattern, new PathTraversalPayload());
    }

    /**
     * Assert that the endpoint is not vulnerable to any common attacks
     *
     * @param string $endpointPattern Endpoint with %s placeholder for payload
     */
    protected function assertSecure(string $endpointPattern): void
    {
        $this->assertNoSqlInjection($endpointPattern);
        $this->assertNoXss($endpointPattern);
        $this->assertNoCommandInjection($endpointPattern);
        $this->assertNoPathTraversal($endpointPattern);
    }

    /**
     * Assert no vulnerability for a specific payload type
     */
    protected function assertNoVulnerability(string $endpointPattern, PayloadInterface $payloadType): void
    {
        if (! isset($this->securityAnalyzer)) {
            $this->initSecurityTesting();
        }

        $vulnerabilities = [];

        foreach ($payloadType->getPayloads() as $payload) {
            $endpoint = sprintf($endpointPattern, urlencode($payload));

            // Use the resource property from WorkflowTest
            /** @var ResourceInterface $resource */
            $resource = $this->resource;
            $response = $resource->get($endpoint);

            $body = (string) $response;
            $code = $response->code;

            $vulnerability = $this->securityAnalyzer->analyze(
                $payloadType,
                $body,
                $code,
                $endpoint,
                $payload,
            );

            if ($vulnerability !== null) {
                $vulnerabilities[] = $vulnerability;
            }
        }

        $this->detectedVulnerabilities = array_merge($this->detectedVulnerabilities, $vulnerabilities);

        $message = sprintf(
            "Endpoint '%s' is vulnerable to %s.\nDetected vulnerabilities:\n%s",
            $endpointPattern,
            $payloadType->getName(),
            $this->formatVulnerabilities($vulnerabilities),
        );

        $this->assertEmpty($vulnerabilities, $message);
    }

    /**
     * Get all detected vulnerabilities
     *
     * @return VulnerabilityInterface[]
     */
    protected function getDetectedVulnerabilities(): array
    {
        return $this->detectedVulnerabilities;
    }

    /**
     * Format vulnerabilities for display in assertion messages
     *
     * @param VulnerabilityInterface[] $vulnerabilities
     */
    private function formatVulnerabilities(array $vulnerabilities): string
    {
        $lines = [];
        foreach ($vulnerabilities as $vuln) {
            $lines[] = sprintf(
                '  - [%s] %s: %s',
                strtoupper($vuln->getSeverity()),
                $vuln->getType(),
                $vuln->getDescription(),
            );
        }

        return implode("\n", $lines);
    }
}
