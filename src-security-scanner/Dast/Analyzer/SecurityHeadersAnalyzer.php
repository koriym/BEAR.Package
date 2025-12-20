<?php

declare(strict_types=1);

namespace BEAR\SecurityScanner\Dast\Analyzer;

use BEAR\SecurityScanner\Vulnerability;
use BEAR\SecurityScanner\VulnerabilityInterface;

use function array_key_exists;
use function preg_match;
use function str_replace;
use function strtolower;
use function strtoupper;

/**
 * Analyzes HTTP response headers for security issues
 */
final class SecurityHeadersAnalyzer
{
    private const REQUIRED_HEADERS = [
        'x-frame-options' => [
            'severity' => VulnerabilityInterface::SEVERITY_MEDIUM,
            'description' => 'Missing X-Frame-Options header - vulnerable to clickjacking',
            'recommendation' => 'Add "X-Frame-Options: DENY" or "X-Frame-Options: SAMEORIGIN" header',
        ],
        'x-content-type-options' => [
            'severity' => VulnerabilityInterface::SEVERITY_LOW,
            'description' => 'Missing X-Content-Type-Options header - vulnerable to MIME sniffing',
            'recommendation' => 'Add "X-Content-Type-Options: nosniff" header',
        ],
        'x-xss-protection' => [
            'severity' => VulnerabilityInterface::SEVERITY_LOW,
            'description' => 'Missing X-XSS-Protection header',
            'recommendation' => 'Add "X-XSS-Protection: 1; mode=block" header (legacy browsers)',
        ],
        'content-security-policy' => [
            'severity' => VulnerabilityInterface::SEVERITY_MEDIUM,
            'description' => 'Missing Content-Security-Policy header - no XSS protection',
            'recommendation' => 'Implement Content-Security-Policy to prevent XSS attacks',
        ],
        'strict-transport-security' => [
            'severity' => VulnerabilityInterface::SEVERITY_MEDIUM,
            'description' => 'Missing Strict-Transport-Security header - vulnerable to downgrade attacks',
            'recommendation' => 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" header',
        ],
        'referrer-policy' => [
            'severity' => VulnerabilityInterface::SEVERITY_LOW,
            'description' => 'Missing Referrer-Policy header - may leak sensitive URL information',
            'recommendation' => 'Add "Referrer-Policy: strict-origin-when-cross-origin" header',
        ],
    ];

    private const INSECURE_VALUES = [
        'x-frame-options' => [
            'pattern' => '/^ALLOW/i',
            'severity' => VulnerabilityInterface::SEVERITY_MEDIUM,
            'description' => 'X-Frame-Options set to ALLOW - clickjacking possible',
            'recommendation' => 'Use "DENY" or "SAMEORIGIN" instead of "ALLOW"',
        ],
        'access-control-allow-origin' => [
            'pattern' => '/^\*$/',
            'severity' => VulnerabilityInterface::SEVERITY_MEDIUM,
            'description' => 'Access-Control-Allow-Origin set to * - allows any origin',
            'recommendation' => 'Restrict CORS to specific trusted origins',
        ],
        'content-security-policy' => [
            'pattern' => '/unsafe-inline|unsafe-eval|\*\s/',
            'severity' => VulnerabilityInterface::SEVERITY_MEDIUM,
            'description' => 'Content-Security-Policy contains unsafe directives',
            'recommendation' => 'Remove unsafe-inline, unsafe-eval, and wildcard (*) from CSP',
        ],
    ];

    /**
     * Analyze response headers for security issues
     *
     * @param array<string, string> $headers Response headers
     * @param string                $url     The URL that was tested
     *
     * @return VulnerabilityInterface[]
     */
    public function analyze(array $headers, string $url): array
    {
        $vulnerabilities = [];

        // Normalize header names to lowercase
        $normalizedHeaders = [];
        foreach ($headers as $name => $value) {
            $normalizedHeaders[strtolower($name)] = $value;
        }

        // Check for missing required headers
        foreach (self::REQUIRED_HEADERS as $header => $config) {
            if (! array_key_exists($header, $normalizedHeaders)) {
                $vulnerabilities[] = new Vulnerability(
                    'MISSING_SECURITY_HEADER_' . strtoupper(str_replace('-', '_', $header)),
                    $config['severity'],
                    $url,
                    0,
                    $config['description'],
                    '',
                    $config['recommendation'],
                );
            }
        }

        // Check for insecure header values
        foreach (self::INSECURE_VALUES as $header => $config) {
            if (array_key_exists($header, $normalizedHeaders)) {
                if (preg_match($config['pattern'], $normalizedHeaders[$header])) {
                    $vulnerabilities[] = new Vulnerability(
                        'INSECURE_HEADER_' . strtoupper(str_replace('-', '_', $header)),
                        $config['severity'],
                        $url,
                        0,
                        $config['description'],
                        $header . ': ' . $normalizedHeaders[$header],
                        $config['recommendation'],
                    );
                }
            }
        }

        // Check for information disclosure headers
        $infoHeaders = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'];
        foreach ($infoHeaders as $header) {
            if (array_key_exists($header, $normalizedHeaders)) {
                $vulnerabilities[] = new Vulnerability(
                    'INFO_DISCLOSURE_' . strtoupper(str_replace('-', '_', $header)),
                    VulnerabilityInterface::SEVERITY_LOW,
                    $url,
                    0,
                    'Server information disclosure via ' . $header . ' header',
                    $header . ': ' . $normalizedHeaders[$header],
                    'Remove or obfuscate the ' . $header . ' header to prevent information disclosure',
                );
            }
        }

        return $vulnerabilities;
    }
}
