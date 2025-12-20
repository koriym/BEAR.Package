<?php

declare(strict_types=1);

namespace BEAR\SecurityScanner\Dast;

use BEAR\SecurityScanner\Dast\Analyzer\ResponseAnalyzer;
use BEAR\SecurityScanner\Dast\Payload\CommandInjectionPayload;
use BEAR\SecurityScanner\Dast\Payload\PathTraversalPayload;
use BEAR\SecurityScanner\Dast\Payload\PayloadInterface;
use BEAR\SecurityScanner\Dast\Payload\SqlInjectionPayload;
use BEAR\SecurityScanner\Dast\Payload\XssPayload;
use BEAR\SecurityScanner\ScanResult;
use BEAR\SecurityScanner\VulnerabilityInterface;

use function array_merge;
use function file_put_contents;
use function microtime;
use function sprintf;
use function urlencode;

use const FILE_APPEND;
use const PHP_EOL;

/**
 * Dynamic Application Security Testing (DAST) Scanner
 *
 * Tests running applications by sending malicious payloads via HTTP
 */
final class DastScanner
{
    /** @var PayloadInterface[] */
    private array $payloads;

    private ResponseAnalyzer $analyzer;

    /** @var callable(string, string): array{code: int, body: string, headers: array<string, string>} */
    private $httpClient;

    private ?string $logFile = null;

    /**
     * @param PayloadInterface[]|null $payloads Custom payloads or null for defaults
     * @param callable|null $httpClient Custom HTTP client function
     */
    public function __construct(?array $payloads = null, ?callable $httpClient = null)
    {
        $this->payloads = $payloads ?? $this->getDefaultPayloads();
        $this->analyzer = new ResponseAnalyzer();
        $this->httpClient = $httpClient ?? [$this, 'defaultHttpClient'];
    }

    /**
     * Set log file for request/response logging
     */
    public function setLogFile(string $logFile): self
    {
        $this->logFile = $logFile;

        return $this;
    }

    /**
     * @return PayloadInterface[]
     */
    private function getDefaultPayloads(): array
    {
        return [
            new SqlInjectionPayload(),
            new XssPayload(),
            new CommandInjectionPayload(),
            new PathTraversalPayload(),
        ];
    }

    /**
     * Scan a single endpoint with all payloads
     *
     * @param string $baseUrl Base URL of the application
     * @param string $endpoint Endpoint path with %s placeholder for payload
     * @param string $method HTTP method (GET, POST, etc.)
     * @param array<string, string> $headers Additional headers
     *
     * @return VulnerabilityInterface[]
     */
    public function scanEndpoint(
        string $baseUrl,
        string $endpoint,
        string $method = 'GET',
        array $headers = []
    ): array {
        $vulnerabilities = [];

        foreach ($this->payloads as $payloadType) {
            $found = $this->testPayloads($baseUrl, $endpoint, $payloadType, $method, $headers);
            $vulnerabilities = array_merge($vulnerabilities, $found);
        }

        return $vulnerabilities;
    }

    /**
     * Scan multiple endpoints
     *
     * @param string $baseUrl Base URL of the application
     * @param string[] $endpoints Array of endpoint paths
     *
     * @return ScanResult
     */
    public function scan(string $baseUrl, array $endpoints): ScanResult
    {
        $startTime = microtime(true);
        $result = new ScanResult();

        foreach ($endpoints as $endpoint) {
            $vulnerabilities = $this->scanEndpoint($baseUrl, $endpoint);
            $result->addVulnerabilities($vulnerabilities);
            $result->incrementFilesScanned(); // Using files as "endpoints scanned"
        }

        $result->setScanTime(microtime(true) - $startTime);

        return $result;
    }

    /**
     * Test a single payload type against an endpoint
     *
     * @return VulnerabilityInterface[]
     */
    private function testPayloads(
        string $baseUrl,
        string $endpoint,
        PayloadInterface $payloadType,
        string $method,
        array $headers
    ): array {
        $vulnerabilities = [];

        foreach ($payloadType->getPayloads() as $payload) {
            $url = $baseUrl . sprintf($endpoint, urlencode($payload));

            $this->log(sprintf("[%s] Testing: %s with payload: %s", $payloadType->getName(), $url, $payload));

            try {
                $response = ($this->httpClient)($url, $method);

                $this->log(sprintf("  Response: %d bytes, code: %d", strlen($response['body']), $response['code']));

                $vulnerability = $this->analyzer->analyze(
                    $payloadType,
                    $response['body'],
                    $response['code'],
                    $url,
                    $payload
                );

                if ($vulnerability !== null) {
                    $vulnerabilities[] = $vulnerability;
                    $this->log(sprintf("  [!] VULNERABILITY DETECTED: %s", $vulnerability->getType()));
                }
            } catch (\Throwable $e) {
                $this->log(sprintf("  [ERROR] %s", $e->getMessage()));
            }
        }

        return $vulnerabilities;
    }

    /**
     * Default HTTP client using file_get_contents
     *
     * @return array{code: int, body: string, headers: array<string, string>}
     */
    private function defaultHttpClient(string $url, string $method): array
    {
        $context = stream_context_create([
            'http' => [
                'method' => $method,
                'ignore_errors' => true,
                'timeout' => 10,
            ],
        ]);

        $body = @file_get_contents($url, false, $context);

        // Parse response code from headers
        $code = 0;
        $responseHeaders = [];
        if (isset($http_response_header)) {
            foreach ($http_response_header as $header) {
                if (preg_match('/^HTTP\/[\d.]+ (\d+)/', $header, $matches)) {
                    $code = (int) $matches[1];
                } elseif (strpos($header, ':') !== false) {
                    [$name, $value] = explode(':', $header, 2);
                    $responseHeaders[trim($name)] = trim($value);
                }
            }
        }

        return [
            'code' => $code,
            'body' => $body ?: '',
            'headers' => $responseHeaders,
        ];
    }

    /**
     * Log message to file if logging is enabled
     */
    private function log(string $message): void
    {
        if ($this->logFile === null) {
            return;
        }

        file_put_contents(
            $this->logFile,
            sprintf("[%s] %s%s", date('Y-m-d H:i:s'), $message, PHP_EOL),
            FILE_APPEND
        );
    }
}
