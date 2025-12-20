<?php

declare(strict_types=1);

namespace BEAR\Package\SecurityScanner;

use BEAR\SecurityScanner\Dast\Analyzer\ResponseAnalyzer;
use BEAR\SecurityScanner\Dast\DastScanner;
use BEAR\SecurityScanner\Dast\Payload\CommandInjectionPayload;
use BEAR\SecurityScanner\Dast\Payload\PathTraversalPayload;
use BEAR\SecurityScanner\Dast\Payload\SqlInjectionPayload;
use BEAR\SecurityScanner\Dast\Payload\XssPayload;
use BEAR\SecurityScanner\VulnerabilityInterface;
use PHPUnit\Framework\TestCase;

class DastScannerTest extends TestCase
{
    public function testSqlInjectionPayloadHasPayloads(): void
    {
        $payload = new SqlInjectionPayload();

        $this->assertNotEmpty($payload->getPayloads());
        $this->assertNotEmpty($payload->getSuccessPatterns());
        $this->assertSame('SQL Injection', $payload->getName());
        $this->assertSame(VulnerabilityInterface::SEVERITY_CRITICAL, $payload->getSeverity());
    }

    public function testXssPayloadHasPayloads(): void
    {
        $payload = new XssPayload();

        $this->assertNotEmpty($payload->getPayloads());
        $this->assertNotEmpty($payload->getSuccessPatterns());
        $this->assertSame('Cross-Site Scripting (XSS)', $payload->getName());
        $this->assertSame(VulnerabilityInterface::SEVERITY_HIGH, $payload->getSeverity());
    }

    public function testCommandInjectionPayloadHasPayloads(): void
    {
        $payload = new CommandInjectionPayload();

        $this->assertNotEmpty($payload->getPayloads());
        $this->assertNotEmpty($payload->getSuccessPatterns());
        $this->assertSame('Command Injection', $payload->getName());
        $this->assertSame(VulnerabilityInterface::SEVERITY_CRITICAL, $payload->getSeverity());
    }

    public function testPathTraversalPayloadHasPayloads(): void
    {
        $payload = new PathTraversalPayload();

        $this->assertNotEmpty($payload->getPayloads());
        $this->assertNotEmpty($payload->getSuccessPatterns());
        $this->assertSame('Path Traversal / LFI', $payload->getName());
        $this->assertSame(VulnerabilityInterface::SEVERITY_HIGH, $payload->getSeverity());
    }

    public function testResponseAnalyzerDetectsSqlError(): void
    {
        $analyzer = new ResponseAnalyzer();
        $payload = new SqlInjectionPayload();

        // Simulate a response containing SQL error
        $responseBody = 'Error: You have an error in your SQL syntax near "SELECT * FROM users"';

        $vulnerability = $analyzer->analyze(
            $payload,
            $responseBody,
            500,
            '/users?id=1',
            "' OR 1=1--"
        );

        $this->assertNotNull($vulnerability);
        $this->assertStringContainsString('SQL', $vulnerability->getType());
    }

    public function testResponseAnalyzerDetectsXss(): void
    {
        $analyzer = new ResponseAnalyzer();
        $payload = new XssPayload();

        // Simulate a response containing reflected XSS
        $responseBody = '<html><body>Search results for: <script>alert(1)</script></body></html>';

        $vulnerability = $analyzer->analyze(
            $payload,
            $responseBody,
            200,
            '/search?q=test',
            '<script>alert(1)</script>'
        );

        $this->assertNotNull($vulnerability);
        $this->assertStringContainsString('XSS', $vulnerability->getType());
    }

    public function testResponseAnalyzerDetectsCommandInjection(): void
    {
        $analyzer = new ResponseAnalyzer();
        $payload = new CommandInjectionPayload();

        // Simulate a response containing command output
        $responseBody = 'Result: uid=33(www-data) gid=33(www-data) groups=33(www-data)';

        $vulnerability = $analyzer->analyze(
            $payload,
            $responseBody,
            200,
            '/ping?host=test',
            '; id'
        );

        $this->assertNotNull($vulnerability);
        $this->assertStringContainsString('COMMAND', $vulnerability->getType());
    }

    public function testResponseAnalyzerDetectsPathTraversal(): void
    {
        $analyzer = new ResponseAnalyzer();
        $payload = new PathTraversalPayload();

        // Simulate /etc/passwd content exposed
        $responseBody = 'root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin';

        $vulnerability = $analyzer->analyze(
            $payload,
            $responseBody,
            200,
            '/file?name=test',
            '../../../etc/passwd'
        );

        $this->assertNotNull($vulnerability);
        $this->assertStringContainsString('PATH', $vulnerability->getType());
    }

    public function testResponseAnalyzerNoFalsePositive(): void
    {
        $analyzer = new ResponseAnalyzer();
        $payload = new SqlInjectionPayload();

        // Normal response should not trigger vulnerability
        $responseBody = '{"users": [{"id": 1, "name": "John"}]}';

        $vulnerability = $analyzer->analyze(
            $payload,
            $responseBody,
            200,
            '/users?id=1',
            "' OR 1=1--"
        );

        $this->assertNull($vulnerability);
    }

    public function testResponseAnalyzerDetectsStackTrace(): void
    {
        $analyzer = new ResponseAnalyzer();
        $payload = new SqlInjectionPayload();

        // Response with stack trace
        $responseBody = 'Error occurred!
Stack trace:
#0 /var/www/app/src/Controller.php(42): doQuery()
#1 /var/www/app/index.php(10): Controller->handle()';

        $vulnerability = $analyzer->analyze(
            $payload,
            $responseBody,
            500,
            '/users?id=1',
            "' OR 1=1--"
        );

        $this->assertNotNull($vulnerability);
        $this->assertSame('DAST_STACK_TRACE_EXPOSURE', $vulnerability->getType());
    }

    public function testDastScannerWithMockHttpClient(): void
    {
        // Create a mock HTTP client that returns a SQL error for any SQL-like payload
        $mockHttpClient = function (string $url, string $method): array {
            // Check if URL contains SQL injection patterns (URL encoded)
            if (preg_match('/(?:OR|UNION|SELECT|DROP)/i', urldecode($url))) {
                return [
                    'code' => 500,
                    'body' => 'Warning: mysql_query(): You have an error in your SQL syntax',
                    'headers' => [],
                ];
            }

            return [
                'code' => 200,
                'body' => '{"status": "ok"}',
                'headers' => [],
            ];
        };

        $scanner = new DastScanner([new SqlInjectionPayload()], $mockHttpClient);
        $vulnerabilities = $scanner->scanEndpoint(
            'http://localhost',
            '/users?id=%s',
            'GET'
        );

        $this->assertNotEmpty($vulnerabilities);
    }

    public function testDastScannerScanMultipleEndpoints(): void
    {
        // Create a mock HTTP client that always returns safe response
        $mockHttpClient = function (string $url, string $method): array {
            return [
                'code' => 200,
                'body' => '{"status": "ok"}',
                'headers' => [],
            ];
        };

        $scanner = new DastScanner(null, $mockHttpClient);
        $result = $scanner->scan('http://localhost', ['/users?id=%s', '/search?q=%s']);

        $this->assertSame(2, $result->getFilesScanned());
        $this->assertGreaterThan(0, $result->getScanTime());
    }

    public function testDastScannerWithLogging(): void
    {
        $logFile = sys_get_temp_dir() . '/dast-test-' . uniqid() . '.log';

        $mockHttpClient = function (string $url, string $method): array {
            return [
                'code' => 200,
                'body' => '{"status": "ok"}',
                'headers' => [],
            ];
        };

        $scanner = new DastScanner([new SqlInjectionPayload()], $mockHttpClient);
        $scanner->setLogFile($logFile);

        // Just test one payload to keep it fast
        $scanner->scanEndpoint('http://localhost', '/test?id=%s');

        $this->assertFileExists($logFile);
        $logContent = file_get_contents($logFile);
        $this->assertStringContainsString('Testing:', $logContent);

        @unlink($logFile);
    }
}
