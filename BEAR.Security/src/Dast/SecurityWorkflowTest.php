<?php

declare(strict_types=1);

namespace BEAR\Security\Dast;

use BEAR\Resource\ResourceInterface;
use BEAR\Security\VulnerabilityInterface;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\TestCase;

use function array_merge;

/**
 * Base class for HTTP-based security workflow testing
 *
 * Extend this class in your BEAR.Sunday application to create
 * security tests that run against a real HTTP server.
 *
 * Example usage in your tests/Http/SecurityWorkflowTest.php:
 * ```php
 * namespace MyVendor\MyApp\Http;
 *
 * use BEAR\Security\Dast\SecurityWorkflowTest as BaseSecurityTest;
 *
 * class SecurityWorkflowTest extends BaseSecurityTest
 * {
 *     protected function setUp(): void
 *     {
 *         $this->resource = new HttpResource(
 *             '127.0.0.1:8080',
 *             __DIR__ . '/index.php',
 *             __DIR__ . '/log/security.log'
 *         );
 *         parent::setUp();
 *     }
 *
 *     public function testUsersEndpointSecurity(): void
 *     {
 *         $this->assertSecure('/users?id=%s');
 *     }
 *
 *     public function testSearchNoXss(): void
 *     {
 *         $this->assertNoXss('/search?q=%s');
 *     }
 * }
 * ```
 */
abstract class SecurityWorkflowTest extends TestCase
{
    use SecurityTest;

    protected ResourceInterface $resource;

    protected function setUp(): void
    {
        parent::setUp();

        $this->initSecurityTesting();
    }

    /**
     * Test that an endpoint returns 200 and check for security issues
     */
    protected function assertEndpointSecure(string $endpoint): void
    {
        // First verify the endpoint works
        $response = $this->resource->get($endpoint);
        $this->assertSame(200, $response->code, "Endpoint $endpoint should return 200");

        // Then run security tests
        $this->assertSecure($endpoint);
    }

    /**
     * Scan all endpoints defined in a sitemap or links
     *
     * @param string[] $endpoints List of endpoint patterns to test
     *
     * @return array{passed: int, failed: int, vulnerabilities: VulnerabilityInterface[]}
     */
    protected function scanEndpoints(array $endpoints): array
    {
        $passed = 0;
        $failed = 0;
        $allVulnerabilities = [];

        foreach ($endpoints as $endpoint) {
            $this->detectedVulnerabilities = [];

            try {
                $this->assertSecure($endpoint);
                $passed++;
            } catch (AssertionFailedError) {
                $failed++;
                $allVulnerabilities = array_merge($allVulnerabilities, $this->detectedVulnerabilities);
            }
        }

        return [
            'passed' => $passed,
            'failed' => $failed,
            'vulnerabilities' => $allVulnerabilities,
        ];
    }
}
