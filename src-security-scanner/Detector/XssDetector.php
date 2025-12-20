<?php

declare(strict_types=1);

namespace BEAR\SecurityScanner\Detector;

use BEAR\SecurityScanner\VulnerabilityInterface;

/**
 * Detects potential Cross-Site Scripting (XSS) vulnerabilities
 */
final class XssDetector extends AbstractDetector
{
    /** @var array<string, array{pattern: string, severity: string, description: string, recommendation: string}> */
    protected array $patterns = [
        'XSS_DIRECT_OUTPUT' => [
            'pattern' => '/(?:echo|print)\s+\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'Direct output of user input without escaping',
            'recommendation' => 'Use htmlspecialchars() or htmlentities() to escape user input before output',
        ],
        'XSS_ECHO_VARIABLE_UNSAFE' => [
            'pattern' => '/echo\s+["\'][^"\']*<[^>]+["\']?\s*\.\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'User input concatenated in HTML output',
            'recommendation' => 'Escape all user input with htmlspecialchars($var, ENT_QUOTES, \'UTF-8\')',
        ],
        'XSS_SHORT_TAG' => [
            'pattern' => '/<\?=\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'Short echo tag outputting user input directly',
            'recommendation' => 'Use <?= htmlspecialchars($var, ENT_QUOTES, \'UTF-8\') ?> instead',
        ],
        'XSS_PRINTF' => [
            'pattern' => '/(?:printf|vprintf)\s*\(\s*["\'][^"\']*<[^>]+[^"\']*["\']\s*,\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)/i',
            'severity' => VulnerabilityInterface::SEVERITY_HIGH,
            'description' => 'printf/vprintf with HTML and user input',
            'recommendation' => 'Escape user input before using in printf with HTML',
        ],
        'XSS_ATTRIBUTE_INJECTION' => [
            'pattern' => '/["\'][^"\']*(?:href|src|onclick|onerror|onload)\s*=\s*["\']?\s*["\']?\s*\.\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)/i',
            'severity' => VulnerabilityInterface::SEVERITY_HIGH,
            'description' => 'User input in HTML attribute - potential attribute injection',
            'recommendation' => 'Validate and escape user input used in HTML attributes',
        ],
        'XSS_JAVASCRIPT_CONTEXT' => [
            'pattern' => '/<script[^>]*>[^<]*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'User input used directly in JavaScript context',
            'recommendation' => 'Use json_encode() for outputting data in JavaScript, never directly inject user input',
        ],
        'XSS_INNERHTML' => [
            'pattern' => '/innerHTML\s*=\s*["\']?[^"\']*\$(?:_GET|_POST|_REQUEST|_COOKIE)/i',
            'severity' => VulnerabilityInterface::SEVERITY_HIGH,
            'description' => 'User input assigned to innerHTML',
            'recommendation' => 'Use textContent instead of innerHTML, or sanitize HTML properly',
        ],
        'XSS_DOCUMENT_WRITE' => [
            'pattern' => '/document\.write\s*\([^)]*\$(?:_GET|_POST|_REQUEST|_COOKIE)/i',
            'severity' => VulnerabilityInterface::SEVERITY_HIGH,
            'description' => 'User input in document.write',
            'recommendation' => 'Avoid document.write with user input; use DOM methods with proper escaping',
        ],
    ];

    public function getName(): string
    {
        return 'XSS (Cross-Site Scripting) Detector';
    }
}
