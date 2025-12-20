<?php

declare(strict_types=1);

namespace BEAR\Security\Detector;

use BEAR\Security\VulnerabilityInterface;

/**
 * Detects potential SQL injection vulnerabilities
 */
final class SqlInjectionDetector extends AbstractDetector
{
    /** @var array<string, array{pattern: string, severity: string, description: string, recommendation: string}> */
    protected array $patterns = [
        'SQL_INJECTION_DIRECT_VARIABLE' => [
            'pattern' => '/(?:mysql_query|mysqli_query|pg_query|sqlite_query)\s*\(\s*[^,]*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'Direct use of user input in SQL query function detected',
            'recommendation' => 'Use prepared statements with parameterized queries instead of directly concatenating user input',
        ],
        'SQL_INJECTION_STRING_CONCAT' => [
            'pattern' => '/(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\s+[^;]*\.\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'User input concatenated directly in SQL query string',
            'recommendation' => 'Use prepared statements (PDO::prepare or mysqli_prepare) with bound parameters',
        ],
        'SQL_INJECTION_DOUBLE_QUOTE' => [
            'pattern' => '/"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^"]*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[[^\]]+\][^"]*"/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'User input interpolated directly in SQL query string',
            'recommendation' => 'Use prepared statements with bound parameters instead of string interpolation',
        ],
        'SQL_INJECTION_PDO_UNSAFE' => [
            'pattern' => '/->(?:query|exec)\s*\(\s*["\'][^"\']*\.\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)/i',
            'severity' => VulnerabilityInterface::SEVERITY_HIGH,
            'description' => 'PDO query or exec with concatenated user input',
            'recommendation' => 'Use PDO::prepare() with bindParam() or bindValue() instead',
        ],
        'SQL_INJECTION_SPRINTF' => [
            'pattern' => '/sprintf\s*\(\s*["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^"\']*%s[^"\']*["\']\s*,\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)/i',
            'severity' => VulnerabilityInterface::SEVERITY_HIGH,
            'description' => 'sprintf used to build SQL query with user input',
            'recommendation' => 'Use prepared statements instead of sprintf for SQL queries',
        ],
        'SQL_INJECTION_POTENTIAL' => [
            'pattern' => '/(?:mysql_query|mysqli_query|pg_query|->query|->exec)\s*\([^)]*\$[a-zA-Z_]\w*\s*\)/i',
            'severity' => VulnerabilityInterface::SEVERITY_MEDIUM,
            'description' => 'Variable used directly in SQL query - verify it is properly sanitized',
            'recommendation' => 'Ensure the variable is properly sanitized or use prepared statements',
        ],
    ];

    public function getName(): string
    {
        return 'SQL Injection Detector';
    }
}
