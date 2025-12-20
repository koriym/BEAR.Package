<?php

declare(strict_types=1);

namespace BEAR\SecurityScanner\Dast\Payload;

use BEAR\SecurityScanner\VulnerabilityInterface;

use function str_repeat;

/**
 * CSRF (Cross-Site Request Forgery) detection payloads
 */
final class CsrfPayload implements PayloadInterface
{
    public function getName(): string
    {
        return 'Cross-Site Request Forgery (CSRF)';
    }

    /** @return string[] */
    public function getPayloads(): array
    {
        return [
            // Empty/missing token
            '',
            'invalid_token',
            'null',
            '0',

            // Malformed tokens
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            '../../../etc/passwd',
            '<script>alert(1)</script>',

            // Token manipulation
            '%00',
            '%0a%0d',
            'undefined',
            'NaN',
            '[]',
            '{}',

            // Length attacks
            str_repeat('A', 1000),
            str_repeat('A', 10000),
        ];
    }

    /** @return string[] */
    public function getSuccessPatterns(): array
    {
        return [
            // Success responses that shouldn't happen without valid CSRF token
            '/success/i',
            '/updated/i',
            '/deleted/i',
            '/created/i',
            '/saved/i',
            '/submitted/i',
            '/completed/i',

            // Redirect after successful action (often indicates success)
            '/302 Found/i',
            '/303 See Other/i',

            // JSON success responses
            '/"success"\s*:\s*true/i',
            '/"status"\s*:\s*"ok"/i',
            '/"error"\s*:\s*false/i',
        ];
    }

    public function getSeverity(): string
    {
        return VulnerabilityInterface::SEVERITY_HIGH;
    }

    public function getDescription(): string
    {
        return 'CSRF vulnerability detected - state-changing action accepted without valid CSRF token';
    }

    public function getRecommendation(): string
    {
        return 'Implement CSRF token validation for all state-changing requests. Use SameSite cookie attribute. Verify Origin/Referer headers.';
    }
}
