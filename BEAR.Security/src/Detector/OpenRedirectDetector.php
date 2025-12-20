<?php

declare(strict_types=1);

namespace BEAR\Security\Detector;

/**
 * Detects Open Redirect vulnerabilities
 */
final class OpenRedirectDetector extends AbstractDetector
{
    /** @var array<string, array{pattern: string, severity: string, description: string, recommendation: string}> */
    protected array $patterns = [
        'OPEN_REDIRECT_HEADER' => [
            'pattern' => '/header\s*\(\s*[\'"]Location:\s*[\'"]\s*\.\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/i',
            'severity' => 'HIGH',
            'description' => 'Open redirect via header() with user-controlled URL',
            'recommendation' => 'Validate redirect URLs against a whitelist of allowed domains or use relative paths only',
        ],
        'OPEN_REDIRECT_HEADER_VAR' => [
            'pattern' => '/header\s*\(\s*[\'"]Location:\s*\$[a-zA-Z_]/i',
            'severity' => 'MEDIUM',
            'description' => 'Potential open redirect - variable used in Location header',
            'recommendation' => 'Ensure the redirect URL is validated against allowed destinations',
        ],
        'OPEN_REDIRECT_META' => [
            'pattern' => '/<meta\s+http-equiv\s*=\s*[\'"]refresh[\'"].*url\s*=\s*.*\$_(GET|POST|REQUEST)/i',
            'severity' => 'HIGH',
            'description' => 'Open redirect via meta refresh with user input',
            'recommendation' => 'Validate redirect URLs before using in meta refresh',
        ],
    ];

    public function getName(): string
    {
        return 'OpenRedirectDetector';
    }
}
