<?php

declare(strict_types=1);

namespace MyVendor\VulnerableApp\Resource\App;

use BEAR\Resource\ResourceObject;
use PDO;

/**
 * Cryptographic and Session vulnerabilities
 */
class Auth extends ResourceObject
{
    // VULNERABILITY: Hardcoded Secret (A02)
    // Detectable by: SAST CryptographicFailuresDetector
    private const API_KEY = 'sk_live_abc123xyz789secret';
    private const DB_PASSWORD = 'super_secret_password_123';

    public function __construct(
        private PDO $pdo,
    ) {
    }

    /**
     * VULNERABILITY: Weak Hash Algorithm (A02)
     * Detectable by: SAST CryptographicFailuresDetector
     */
    public function onPost(string $username, string $password): static
    {
        // BAD: MD5 for password hashing
        $hash = md5($password);

        $stmt = $this->pdo->prepare('SELECT * FROM users WHERE username = ? AND password = ?');
        $stmt->execute([$username, $hash]);

        if ($user = $stmt->fetch()) {
            // VULNERABILITY: Session Fixation (A07)
            // Detectable by: SAST SessionSecurityDetector
            // Missing: session_regenerate_id(true);
            $_SESSION['user_id'] = $user['id'];
        }

        return $this;
    }

    /**
     * VULNERABILITY: Insecure Deserialization (A08)
     * Detectable by: SAST InsecureDeserializationDetector
     */
    public function onPut(string $token): static
    {
        // BAD: Unserializing user input
        $data = unserialize(base64_decode($token));
        $this->body = $data;

        return $this;
    }

    /**
     * AI-ONLY: Timing Attack in Password Comparison
     * String comparison leaks password length through timing
     */
    public function validateApiKey(string $providedKey): bool
    {
        // BAD: Vulnerable to timing attack
        // Should use hash_equals()
        return $providedKey === self::API_KEY;
    }
}
