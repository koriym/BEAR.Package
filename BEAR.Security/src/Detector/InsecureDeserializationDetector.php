<?php

declare(strict_types=1);

namespace BEAR\Security\Detector;

use BEAR\Security\VulnerabilityInterface;

/**
 * Detects insecure deserialization vulnerabilities (OWASP A08)
 *
 * Unsafe deserialization can lead to:
 * - Remote Code Execution (RCE)
 * - Denial of Service (DoS)
 * - Authentication bypass
 */
final class InsecureDeserializationDetector extends AbstractDetector
{
    /** @var array<string, array{pattern: string, severity: string, description: string, recommendation: string}> */
    protected array $patterns = [
        // PHP unserialize with user input
        'INSECURE_UNSERIALIZE_GET' => [
            'pattern' => '/\bunserialize\s*\(\s*\$_GET\s*\[/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'unserialize() called with $_GET data - critical RCE risk',
            'recommendation' => 'Never unserialize untrusted data. Use JSON (json_decode) instead',
        ],
        'INSECURE_UNSERIALIZE_POST' => [
            'pattern' => '/\bunserialize\s*\(\s*\$_POST\s*\[/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'unserialize() called with $_POST data - critical RCE risk',
            'recommendation' => 'Never unserialize untrusted data. Use JSON (json_decode) instead',
        ],
        'INSECURE_UNSERIALIZE_REQUEST' => [
            'pattern' => '/\bunserialize\s*\(\s*\$_REQUEST\s*\[/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'unserialize() called with $_REQUEST data - critical RCE risk',
            'recommendation' => 'Never unserialize untrusted data. Use JSON (json_decode) instead',
        ],
        'INSECURE_UNSERIALIZE_COOKIE' => [
            'pattern' => '/\bunserialize\s*\(\s*\$_COOKIE\s*\[/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'unserialize() called with $_COOKIE data - critical RCE risk',
            'recommendation' => 'Never unserialize untrusted data. Use JSON (json_decode) instead',
        ],
        'INSECURE_UNSERIALIZE_FILE' => [
            'pattern' => '/\bunserialize\s*\(\s*file_get_contents\s*\(/i',
            'severity' => VulnerabilityInterface::SEVERITY_HIGH,
            'description' => 'unserialize() called with file contents - verify file source is trusted',
            'recommendation' => 'Ensure file source is trusted or use JSON format instead',
        ],
        'INSECURE_UNSERIALIZE_BASE64' => [
            'pattern' => '/\bunserialize\s*\(\s*base64_decode\s*\(/i',
            'severity' => VulnerabilityInterface::SEVERITY_HIGH,
            'description' => 'unserialize() with base64 decode - often used with user input',
            'recommendation' => 'Verify data source is trusted or use signed/encrypted data',
        ],
        'INSECURE_UNSERIALIZE_VARIABLE' => [
            'pattern' => '/\bunserialize\s*\(\s*\$[a-zA-Z_]\w*\s*\)/i',
            'severity' => VulnerabilityInterface::SEVERITY_MEDIUM,
            'description' => 'unserialize() called with variable - verify data source',
            'recommendation' => 'Ensure variable contains trusted data or use json_decode()',
        ],

        // YAML parsing (can execute code)
        'INSECURE_YAML_PARSE' => [
            'pattern' => '/\byaml_parse\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'yaml_parse() with user input can execute arbitrary PHP code',
            'recommendation' => 'Use yaml_parse() with YAML_OBJECT_DISABLED or Symfony YAML component',
        ],
        'INSECURE_YAML_PARSE_FILE' => [
            'pattern' => '/\byaml_parse_file\s*\(\s*\$(?:_GET|_POST|_REQUEST)\s*\[/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'yaml_parse_file() with user-controlled path',
            'recommendation' => 'Validate and whitelist allowed YAML files',
        ],

        // Object injection via magic methods
        'WAKEUP_DANGEROUS' => [
            'pattern' => '/function\s+__wakeup\s*\(\s*\)[^{]*\{[^}]*(?:exec|system|passthru|shell_exec|eval|include|require)/is',
            'severity' => VulnerabilityInterface::SEVERITY_HIGH,
            'description' => '__wakeup() contains dangerous functions - exploitable via unserialize',
            'recommendation' => 'Remove dangerous operations from __wakeup() or implement __serialize()/__unserialize()',
        ],
        'DESTRUCT_DANGEROUS' => [
            'pattern' => '/function\s+__destruct\s*\(\s*\)[^{]*\{[^}]*(?:exec|system|passthru|shell_exec|eval|unlink|file_put_contents)/is',
            'severity' => VulnerabilityInterface::SEVERITY_HIGH,
            'description' => '__destruct() contains dangerous functions - exploitable via unserialize',
            'recommendation' => 'Validate object state in __destruct() before performing operations',
        ],

        // Phar deserialization
        'PHAR_WRAPPER_USER_INPUT' => [
            'pattern' => '/(?:file_exists|is_file|is_dir|file_get_contents|fopen|include|require)\s*\(\s*["\']phar:\/\/["\']?\s*\.\s*\$/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'Phar wrapper with user input can trigger deserialization',
            'recommendation' => 'Validate file paths and disable phar wrapper if not needed',
        ],
    ];

    public function getName(): string
    {
        return 'Insecure Deserialization Detector';
    }
}
