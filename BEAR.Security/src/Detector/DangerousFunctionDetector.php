<?php

declare(strict_types=1);

namespace BEAR\Security\Detector;

use BEAR\Security\VulnerabilityInterface;

/**
 * Detects usage of dangerous PHP functions
 */
final class DangerousFunctionDetector extends AbstractDetector
{
    /** @var array<string, array{pattern: string, severity: string, description: string, recommendation: string}> */
    protected array $patterns = [
        'DANGEROUS_EVAL' => [
            'pattern' => '/\beval\s*\(/i',
            'severity' => VulnerabilityInterface::SEVERITY_HIGH,
            'description' => 'Usage of eval() function detected',
            'recommendation' => 'Avoid eval(); refactor to use safer alternatives like anonymous functions or data structures',
        ],
        'DANGEROUS_EXEC' => [
            'pattern' => '/\b(?:exec|shell_exec|system|passthru|popen|proc_open)\s*\(/i',
            'severity' => VulnerabilityInterface::SEVERITY_MEDIUM,
            'description' => 'Shell command execution function detected',
            'recommendation' => 'Use escapeshellarg()/escapeshellcmd() for input sanitization, or use safer alternatives',
        ],
        'DANGEROUS_BACKTICK' => [
            'pattern' => '/^\s*[^\/\*]*`[^`]+`/m',
            'severity' => VulnerabilityInterface::SEVERITY_MEDIUM,
            'description' => 'Backtick operator (shell execution) detected',
            'recommendation' => 'Use explicit shell functions with proper escaping instead of backticks',
        ],
        'DANGEROUS_CREATE_FUNCTION' => [
            'pattern' => '/\bcreate_function\s*\(/i',
            'severity' => VulnerabilityInterface::SEVERITY_HIGH,
            'description' => 'Deprecated create_function() detected',
            'recommendation' => 'Use anonymous functions (closures) instead - create_function is deprecated in PHP 7.2+',
        ],
        'DANGEROUS_UNSERIALIZE' => [
            'pattern' => '/\bunserialize\s*\(/i',
            'severity' => VulnerabilityInterface::SEVERITY_MEDIUM,
            'description' => 'unserialize() usage detected - potential object injection',
            'recommendation' => 'Use json_decode() for data deserialization, or specify allowed_classes parameter',
        ],
        'DANGEROUS_PREG_REPLACE_E' => [
            'pattern' => '/preg_replace\s*\(\s*["\'][^"\']*\/e["\']/',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'preg_replace with /e modifier - code execution vulnerability',
            'recommendation' => 'Use preg_replace_callback() instead - /e modifier is removed in PHP 7.0+',
        ],
        'DANGEROUS_EXTRACT' => [
            'pattern' => '/\bextract\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE|_SERVER)/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'extract() used on superglobal - variable injection vulnerability',
            'recommendation' => 'Access superglobal values directly instead of using extract()',
        ],
        'DANGEROUS_PARSE_STR' => [
            'pattern' => '/\bparse_str\s*\(\s*\$\w+\s*\)\s*;/i',
            'severity' => VulnerabilityInterface::SEVERITY_HIGH,
            'description' => 'parse_str() with single variable argument - potential variable overwrite vulnerability',
            'recommendation' => 'Always use the second parameter: parse_str($string, $result)',
        ],
        'DANGEROUS_VAR_EXPORT' => [
            'pattern' => '/\bvar_export\s*\([^)]+,\s*true\s*\).*include|include.*\bvar_export\s*\([^)]+,\s*true\s*\)/is',
            'severity' => VulnerabilityInterface::SEVERITY_MEDIUM,
            'description' => 'var_export used for caching - potential code injection if data is user-controlled',
            'recommendation' => 'Use serialize/json_encode for caching, or validate data strictly',
        ],
        'DANGEROUS_CALL_USER_FUNC' => [
            'pattern' => '/\b(?:call_user_func|call_user_func_array)\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'call_user_func with user input - arbitrary function execution',
            'recommendation' => 'Use a whitelist of allowed functions instead of user-controlled function names',
        ],
        'DANGEROUS_VARIABLE_FUNCTION' => [
            'pattern' => '/\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[[^\]]+\]\s*\(/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'Variable function call with user input - arbitrary function execution',
            'recommendation' => 'Use a whitelist of allowed functions and explicit switch/if statements',
        ],
        'DANGEROUS_VARIABLE_VARIABLE' => [
            'pattern' => '/\$\$(?:_GET|_POST|_REQUEST|_COOKIE)/i',
            'severity' => VulnerabilityInterface::SEVERITY_HIGH,
            'description' => 'Variable variable with user input - variable overwrite vulnerability',
            'recommendation' => 'Avoid variable variables with user input; use explicit array access',
        ],
    ];

    public function getName(): string
    {
        return 'Dangerous Function Detector';
    }
}
