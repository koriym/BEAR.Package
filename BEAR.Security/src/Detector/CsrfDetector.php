<?php

declare(strict_types=1);

namespace BEAR\Security\Detector;

/**
 * Detects Cross-Site Request Forgery (CSRF) vulnerabilities
 */
final class CsrfDetector extends AbstractDetector
{
    /** @return array<string, array{pattern: string, severity: string, description: string, recommendation: string}> */
    protected function getPatterns(): array
    {
        return [
            'CSRF_FORM_NO_TOKEN' => [
                'pattern' => '/<form[^>]+method\s*=\s*["\']?post["\']?[^>]*>(?:(?!csrf|token|_token|authenticity_token).)*?<\/form>/is',
                'severity' => 'high',
                'description' => 'Form with POST method lacks CSRF token',
                'recommendation' => 'Add CSRF token field to all forms. Use framework-provided CSRF protection.',
            ],
            'CSRF_NO_TOKEN_CHECK' => [
                'pattern' => '/\$_(POST|REQUEST)\s*\[[^\]]+\](?:(?!csrf|token|verify|validate).){0,200}(insert|update|delete|execute|query)/is',
                'severity' => 'medium',
                'description' => 'POST data used without apparent CSRF token validation',
                'recommendation' => 'Validate CSRF token before processing state-changing requests.',
            ],
            'CSRF_SESSION_NO_TOKEN' => [
                'pattern' => '/\$_SESSION\s*\[[^\]]+\]\s*=\s*\$_(POST|REQUEST|GET)\[/i',
                'severity' => 'medium',
                'description' => 'Session modification from user input without CSRF check',
                'recommendation' => 'Always validate CSRF token before modifying session data.',
            ],
            'CSRF_COOKIE_NO_SAMESITE' => [
                'pattern' => '/setcookie\s*\([^)]+\)(?![^;]*SameSite)/i',
                'severity' => 'low',
                'description' => 'Cookie set without SameSite attribute',
                'recommendation' => 'Set SameSite=Strict or SameSite=Lax on cookies to prevent CSRF.',
            ],
        ];
    }

    public function getName(): string
    {
        return 'CSRF Detector';
    }
}
