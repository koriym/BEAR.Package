<?php

declare(strict_types=1);

namespace BEAR\Security\Detector;

/**
 * Detects HTTP Header Injection vulnerabilities
 */
final class HeaderInjectionDetector extends AbstractDetector
{
    /** @var array<string, array{pattern: string, severity: string, description: string, recommendation: string}> */
    protected array $patterns = [
        'HEADER_INJECTION_USER_INPUT' => [
            'pattern' => '/header\s*\(\s*[^)]*\.\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/i',
            'severity' => 'HIGH',
            'description' => 'HTTP header injection - user input in header() without sanitization',
            'recommendation' => 'Remove newlines from user input: str_replace(["\r", "\n"], "", $input)',
        ],
        'HEADER_INJECTION_COOKIE' => [
            'pattern' => '/setcookie\s*\(\s*[^,]+,\s*\$_(GET|POST|REQUEST)\s*\[/i',
            'severity' => 'HIGH',
            'description' => 'Cookie value from user input may allow header injection',
            'recommendation' => 'Sanitize cookie values and use httponly/secure flags',
        ],
        'HEADER_INJECTION_SETRAWCOOKIE' => [
            'pattern' => '/setrawcookie\s*\(\s*[^,]+,\s*\$_(GET|POST|REQUEST)\s*\[/i',
            'severity' => 'HIGH',
            'description' => 'Raw cookie with user input - high risk of header injection',
            'recommendation' => 'Use setcookie() with proper encoding or validate input strictly',
        ],
        'HEADER_INJECTION_CONTENT_TYPE' => [
            'pattern' => '/header\s*\(\s*[\'"]Content-Type:\s*[\'"].*\$_(GET|POST|REQUEST)/i',
            'severity' => 'MEDIUM',
            'description' => 'User-controlled Content-Type header',
            'recommendation' => 'Use whitelist for allowed content types',
        ],
    ];

    public function getName(): string
    {
        return 'HeaderInjectionDetector';
    }
}
