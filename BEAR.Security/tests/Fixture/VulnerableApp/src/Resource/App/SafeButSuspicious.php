<?php

declare(strict_types=1);

namespace MyVendor\VulnerableApp\Resource\App;

use BEAR\Resource\ResourceObject;
use PDO;

/**
 * Safe code that may trigger false positives
 * AI should recognize these as safe
 */
class SafeButSuspicious extends ResourceObject
{
    public function __construct(
        private PDO $pdo,
    ) {
    }

    /**
     * FALSE POSITIVE: Looks like SQL injection but uses prepared statement
     */
    public function onGet(string $id): static
    {
        // This variable name looks dangerous but usage is safe
        $userInput = $id;
        $query = 'SELECT * FROM users WHERE id = ?';

        // Safe: prepared statement with parameter binding
        $stmt = $this->pdo->prepare($query);
        $stmt->execute([$userInput]);
        $this->body = $stmt->fetch();

        return $this;
    }

    /**
     * FALSE POSITIVE: Variable named $password but it's a hash comparison
     */
    public function verifyPassword(string $password, string $hash): bool
    {
        // Safe: using password_verify, not plain comparison
        return password_verify($password, $hash);
    }

    /**
     * FALSE POSITIVE: exec() but not shell_exec - it's PDO::exec for DDL
     */
    public function createTable(): void
    {
        // Safe: hardcoded SQL, no user input
        $this->pdo->exec('CREATE TABLE IF NOT EXISTS cache (key VARCHAR(255), value TEXT)');
    }

    /**
     * FALSE POSITIVE: Looks like command injection but input is validated
     */
    public function onPost(string $filename): static
    {
        // Safe: whitelist validation
        $allowed = ['report.pdf', 'summary.pdf', 'data.csv'];
        if (! in_array($filename, $allowed, true)) {
            throw new \InvalidArgumentException('Invalid filename');
        }

        $output = shell_exec('cat /var/reports/' . escapeshellarg($filename));
        $this->body = ['content' => $output];

        return $this;
    }

    /**
     * FALSE POSITIVE: serialize() but on internal data only
     */
    public function cacheData(array $data): string
    {
        // Safe: serializing internal data, not user input
        return serialize(['timestamp' => time(), 'data' => $data]);
    }

    /**
     * FALSE POSITIVE: file_get_contents but with validated internal path
     */
    public function loadTemplate(string $name): string
    {
        // Safe: basename removes path traversal, extension is fixed
        $safeName = basename($name);
        $path = __DIR__ . '/../../templates/' . $safeName . '.html';

        if (! file_exists($path)) {
            throw new \RuntimeException('Template not found');
        }

        return file_get_contents($path);
    }

    /**
     * FALSE POSITIVE: Looks like hardcoded secret but it's a placeholder
     */
    public function getConfig(): array
    {
        return [
            // Safe: placeholder values, real values from env
            'api_key' => getenv('API_KEY') ?: 'YOUR_API_KEY_HERE',
            'db_password' => getenv('DB_PASSWORD') ?: 'REPLACE_WITH_REAL_PASSWORD',
        ];
    }

    /**
     * FALSE POSITIVE: md5() but for non-security purpose
     */
    public function getCacheKey(string $url): string
    {
        // Safe: MD5 for cache key generation, not password hashing
        return 'cache_' . md5($url);
    }

    /**
     * FALSE POSITIVE: eval-like but it's json_decode
     */
    public function parseJson(string $json): mixed
    {
        // Safe: json_decode is not eval
        return json_decode($json, true, 512, JSON_THROW_ON_ERROR);
    }
}
