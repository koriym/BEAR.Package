<?php

declare(strict_types=1);

namespace BEAR\Security\Detector;

use BEAR\Security\VulnerabilityInterface;

/**
 * Detects session-related security issues
 */
final class SessionSecurityDetector extends AbstractDetector
{
    /** @var array<string, array{pattern: string, severity: string, description: string, recommendation: string}> */
    protected array $patterns = [
        'SESSION_FIXATION' => [
            'pattern' => '/\$_SESSION\s*\[[^\]]+\]\s*=\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[[^\]]*(?:session|sid|id)[^\]]*\]/i',
            'severity' => VulnerabilityInterface::SEVERITY_HIGH,
            'description' => 'Potential session fixation - user input assigned to session',
            'recommendation' => 'Regenerate session ID with session_regenerate_id(true) after authentication',
        ],
        'SESSION_COOKIE_HTTPONLY_MISSING' => [
            'pattern' => '/session_set_cookie_params\s*\([^)]*\)\s*(?!.*httponly)/is',
            'severity' => VulnerabilityInterface::SEVERITY_MEDIUM,
            'description' => 'session_set_cookie_params without httponly flag',
            'recommendation' => 'Set httponly flag to prevent JavaScript access to session cookie',
        ],
        'SESSION_COOKIE_SECURE_MISSING' => [
            'pattern' => '/ini_set\s*\(\s*["\']session\.cookie_secure["\']\s*,\s*["\']?(?:0|false|off)["\']?\s*\)/i',
            'severity' => VulnerabilityInterface::SEVERITY_MEDIUM,
            'description' => 'Session cookie secure flag explicitly disabled',
            'recommendation' => 'Enable session.cookie_secure for HTTPS-only cookie transmission',
        ],
        'SESSION_USE_TRANS_SID' => [
            'pattern' => '/ini_set\s*\(\s*["\']session\.use_trans_sid["\']\s*,\s*["\']?(?:1|true|on)["\']?\s*\)/i',
            'severity' => VulnerabilityInterface::SEVERITY_HIGH,
            'description' => 'Transparent session ID enabled - session ID exposed in URLs',
            'recommendation' => 'Disable session.use_trans_sid to prevent session ID leakage',
        ],
        'SESSION_DIRECT_ID_ASSIGNMENT' => [
            'pattern' => '/session_id\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'User input directly used to set session ID',
            'recommendation' => 'Never set session ID from user input; use session_regenerate_id()',
        ],
        'CSRF_NO_TOKEN' => [
            'pattern' => '/<form[^>]+method\s*=\s*["\']post["\'][^>]*>(?:(?!csrf|token|_token|nonce)[^<]|<(?!\/form))*<\/form>/is',
            'severity' => VulnerabilityInterface::SEVERITY_LOW,
            'description' => 'POST form without visible CSRF token (may be false positive)',
            'recommendation' => 'Include CSRF token in all POST forms for protection against CSRF attacks',
        ],
    ];

    public function getName(): string
    {
        return 'Session Security Detector';
    }
}
