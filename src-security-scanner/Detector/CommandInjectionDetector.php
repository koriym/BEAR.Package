<?php

declare(strict_types=1);

namespace BEAR\SecurityScanner\Detector;

use BEAR\SecurityScanner\VulnerabilityInterface;

/**
 * Detects potential Command Injection vulnerabilities
 */
final class CommandInjectionDetector extends AbstractDetector
{
    /** @var array<string, array{pattern: string, severity: string, description: string, recommendation: string}> */
    protected array $patterns = [
        'COMMAND_INJECTION_EXEC' => [
            'pattern' => '/\b(?:exec|shell_exec|system|passthru|popen|proc_open)\s*\([^)]*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'User input passed directly to command execution function',
            'recommendation' => 'Use escapeshellarg() and escapeshellcmd() to sanitize input, or avoid shell commands entirely',
        ],
        'COMMAND_INJECTION_BACKTICK' => [
            'pattern' => '/`[^`]*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[[^\]]+\][^`]*`/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'User input in backtick operator (shell execution)',
            'recommendation' => 'Avoid backtick operator with user input; use escapeshellarg() if shell execution is necessary',
        ],
        'COMMAND_INJECTION_CONCAT' => [
            'pattern' => '/\b(?:exec|shell_exec|system|passthru|popen|proc_open)\s*\([^)]*\.\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'User input concatenated into command execution',
            'recommendation' => 'Sanitize all user input with escapeshellarg() before concatenation',
        ],
        'COMMAND_INJECTION_VARIABLE' => [
            'pattern' => '/\b(?:exec|shell_exec|system|passthru)\s*\(\s*\$[a-zA-Z_]\w*\s*\)/i',
            'severity' => VulnerabilityInterface::SEVERITY_MEDIUM,
            'description' => 'Variable passed to command execution - verify proper sanitization',
            'recommendation' => 'Ensure the variable is sanitized with escapeshellarg() or escapeshellcmd()',
        ],
        'COMMAND_INJECTION_EVAL' => [
            'pattern' => '/\beval\s*\([^)]*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'User input in eval() - extremely dangerous',
            'recommendation' => 'Never use eval() with user input; refactor to use safer alternatives',
        ],
        'COMMAND_INJECTION_PREG_REPLACE' => [
            'pattern' => '/preg_replace\s*\(\s*["\'][^"\']*\/e["\'].*\$(?:_GET|_POST|_REQUEST|_COOKIE)/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'preg_replace with /e modifier and user input - code execution vulnerability',
            'recommendation' => 'Use preg_replace_callback() instead of /e modifier',
        ],
        'COMMAND_INJECTION_ASSERT' => [
            'pattern' => '/\bassert\s*\([^)]*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'User input in assert() - potential code execution',
            'recommendation' => 'Never use assert() with user input',
        ],
        'COMMAND_INJECTION_CREATE_FUNCTION' => [
            'pattern' => '/\bcreate_function\s*\([^)]*\$(?:_GET|_POST|_REQUEST|_COOKIE)/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'User input in create_function() - deprecated and dangerous',
            'recommendation' => 'Use anonymous functions (closures) instead of create_function()',
        ],
    ];

    public function getName(): string
    {
        return 'Command Injection Detector';
    }
}
