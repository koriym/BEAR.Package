<?php

declare(strict_types=1);

namespace MyVendor\VulnerableApp\Resource\App;

use BEAR\Resource\ResourceObject;
use PDO;

/**
 * Intentionally vulnerable resource for testing BEAR.Security
 * DO NOT use this code in production!
 */
class User extends ResourceObject
{
    public function __construct(
        private PDO $pdo,
    ) {
    }

    /**
     * VULNERABILITY: SQL Injection (A03)
     * Detectable by: SAST SqlInjectionDetector
     */
    public function onGet(string $id): static
    {
        // BAD: Direct string concatenation
        $sql = "SELECT * FROM users WHERE id = " . $id;
        $this->body = $this->pdo->query($sql)->fetch();

        return $this;
    }

    /**
     * VULNERABILITY: SQL Injection via POST
     * Detectable by: SAST SqlInjectionDetector
     */
    public function onPost(string $name, string $email): static
    {
        // BAD: Using $_POST directly
        $sql = "INSERT INTO users (name, email) VALUES ('{$_POST['name']}', '{$_POST['email']}')";
        $this->pdo->exec($sql);

        return $this;
    }
}
