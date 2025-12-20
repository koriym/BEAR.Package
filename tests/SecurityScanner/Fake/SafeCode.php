<?php

declare(strict_types=1);

namespace BEAR\Package\SecurityScanner\Fake;

/**
 * This file contains safe code patterns that should NOT trigger the security scanner
 */
class SafeCode
{
    // Safe SQL with prepared statements
    public function safeSql(\PDO $pdo, string $id): array
    {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$id]);
        return $stmt->fetchAll();
    }

    // Safe output with escaping
    public function safeOutput(string $message): void
    {
        echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
    }

    // Safe command execution with escaping
    public function safeCommand(string $filename): string
    {
        $safeFilename = escapeshellarg($filename);
        return shell_exec("cat $safeFilename") ?? '';
    }

    // Safe file operations with validation
    public function safeFileRead(string $filename): string
    {
        $basePath = '/var/www/files/';
        $realPath = realpath($basePath . basename($filename));

        if ($realPath === false || strpos($realPath, $basePath) !== 0) {
            throw new \InvalidArgumentException('Invalid file path');
        }

        return file_get_contents($realPath) ?: '';
    }

    // Safe assert with instanceof (type assertion)
    public function safeAssert(object $obj): void
    {
        assert($obj instanceof \stdClass);
    }

    // Safe parse_str with second parameter
    public function safeParseStr(string $queryString): array
    {
        parse_str($queryString, $result);
        return $result;
    }

    // Safe unserialize with allowed_classes
    public function safeUnserialize(string $data): mixed
    {
        return unserialize($data, ['allowed_classes' => false]);
    }
}
