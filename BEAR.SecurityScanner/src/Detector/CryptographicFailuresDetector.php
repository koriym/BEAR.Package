<?php

declare(strict_types=1);

namespace BEAR\SecurityScanner\Detector;

use BEAR\SecurityScanner\VulnerabilityInterface;

/**
 * Detects cryptographic failures (OWASP A02)
 *
 * - Weak hash functions for passwords
 * - Insecure random number generation
 * - Hardcoded secrets and credentials
 * - Deprecated encryption functions
 */
final class CryptographicFailuresDetector extends AbstractDetector
{
    /** @var array<string, array{pattern: string, severity: string, description: string, recommendation: string}> */
    protected array $patterns = [
        // Weak hash functions for passwords
        'WEAK_HASH_MD5_PASSWORD' => [
            'pattern' => '/md5\s*\(\s*\$(?:password|passwd|pass|pwd|secret|credentials?)\b/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'MD5 used for password hashing - cryptographically broken',
            'recommendation' => 'Use password_hash() with PASSWORD_DEFAULT or PASSWORD_ARGON2ID',
        ],
        'WEAK_HASH_SHA1_PASSWORD' => [
            'pattern' => '/sha1\s*\(\s*\$(?:password|passwd|pass|pwd|secret|credentials?)\b/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'SHA1 used for password hashing - cryptographically weak',
            'recommendation' => 'Use password_hash() with PASSWORD_DEFAULT or PASSWORD_ARGON2ID',
        ],
        'WEAK_HASH_MD5_GENERAL' => [
            'pattern' => '/\bmd5\s*\(/i',
            'severity' => VulnerabilityInterface::SEVERITY_MEDIUM,
            'description' => 'MD5 hash function used - weak for security purposes',
            'recommendation' => 'Use SHA-256 or stronger (hash("sha256", $data)) for integrity, password_hash() for passwords',
        ],
        'WEAK_HASH_SHA1_GENERAL' => [
            'pattern' => '/\bsha1\s*\(/i',
            'severity' => VulnerabilityInterface::SEVERITY_LOW,
            'description' => 'SHA1 hash function used - consider using SHA-256 or stronger',
            'recommendation' => 'Use hash("sha256", $data) or hash("sha3-256", $data) for better security',
        ],

        // Insecure random number generation
        'INSECURE_RANDOM_RAND' => [
            'pattern' => '/\brand\s*\(\s*\)/i',
            'severity' => VulnerabilityInterface::SEVERITY_HIGH,
            'description' => 'rand() is not cryptographically secure',
            'recommendation' => 'Use random_int() or random_bytes() for cryptographic purposes',
        ],
        'INSECURE_RANDOM_MT_RAND' => [
            'pattern' => '/\bmt_rand\s*\(/i',
            'severity' => VulnerabilityInterface::SEVERITY_HIGH,
            'description' => 'mt_rand() is not cryptographically secure',
            'recommendation' => 'Use random_int() for random integers or random_bytes() for random data',
        ],
        'INSECURE_RANDOM_SHUFFLE' => [
            'pattern' => '/\bshuffle\s*\(/i',
            'severity' => VulnerabilityInterface::SEVERITY_LOW,
            'description' => 'shuffle() uses non-cryptographic randomness',
            'recommendation' => 'For security-sensitive shuffling, use a custom Fisher-Yates with random_int()',
        ],
        'INSECURE_RANDOM_UNIQID' => [
            'pattern' => '/\buniqid\s*\([^)]*\)\s*(?:;|\.|\)|\])/i',
            'severity' => VulnerabilityInterface::SEVERITY_MEDIUM,
            'description' => 'uniqid() is not suitable for security tokens',
            'recommendation' => 'Use bin2hex(random_bytes(32)) for secure tokens',
        ],

        // Hardcoded secrets
        'HARDCODED_PASSWORD' => [
            'pattern' => '/\$(?:password|passwd|pass|pwd)\s*=\s*["\'][^"\']{4,}["\']\s*;/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'Hardcoded password detected in source code',
            'recommendation' => 'Use environment variables or secure configuration management',
        ],
        'HARDCODED_API_KEY' => [
            'pattern' => '/\$(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*=\s*["\'][a-zA-Z0-9_\-]{16,}["\']\s*;/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'Hardcoded API key or secret token detected',
            'recommendation' => 'Store secrets in environment variables or use a secrets manager',
        ],
        'HARDCODED_DB_PASSWORD' => [
            'pattern' => '/(?:define\s*\(\s*["\'](?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD)["\']|["\'](?:password|pwd)["\'])\s*(?:,|=>)\s*["\'][^"\']{4,}["\']/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'Hardcoded database password detected',
            'recommendation' => 'Use environment variables: getenv("DB_PASSWORD") or $_ENV["DB_PASSWORD"]',
        ],
        'HARDCODED_PRIVATE_KEY' => [
            'pattern' => '/-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'Private key embedded in source code',
            'recommendation' => 'Store private keys in secure files outside the codebase with proper permissions',
        ],
        'HARDCODED_AWS_KEY' => [
            'pattern' => '/(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'Potential AWS access key ID detected in source code',
            'recommendation' => 'Use IAM roles, environment variables, or AWS Secrets Manager',
        ],

        // Deprecated encryption
        'DEPRECATED_MCRYPT' => [
            'pattern' => '/\bmcrypt_(?:encrypt|decrypt|module_open|generic|cbc|cfb|ecb|ofb)\s*\(/i',
            'severity' => VulnerabilityInterface::SEVERITY_HIGH,
            'description' => 'mcrypt extension is deprecated and removed in PHP 7.2+',
            'recommendation' => 'Use openssl_encrypt() and openssl_decrypt() with AES-256-GCM',
        ],
        'WEAK_CIPHER_DES' => [
            'pattern' => '/(?:MCRYPT_DES|DES-|des-(?:cbc|ecb|cfb|ofb)|openssl.*["\'](?:des|des3|3des)["\'])/i',
            'severity' => VulnerabilityInterface::SEVERITY_HIGH,
            'description' => 'DES/3DES encryption is weak and deprecated',
            'recommendation' => 'Use AES-256-GCM or AES-256-CBC with HMAC',
        ],
        'WEAK_CIPHER_RC4' => [
            'pattern' => '/(?:MCRYPT_ARCFOUR|rc4|arcfour)/i',
            'severity' => VulnerabilityInterface::SEVERITY_HIGH,
            'description' => 'RC4 cipher is cryptographically broken',
            'recommendation' => 'Use AES-256-GCM or ChaCha20-Poly1305',
        ],
        'ECB_MODE' => [
            'pattern' => '/(?:MCRYPT_MODE_ECB|aes-\d+-ecb|["\']ecb["\'])/i',
            'severity' => VulnerabilityInterface::SEVERITY_HIGH,
            'description' => 'ECB mode does not provide semantic security',
            'recommendation' => 'Use GCM mode (AES-256-GCM) or CBC with HMAC',
        ],

        // Insecure password verification
        'INSECURE_PASSWORD_COMPARE' => [
            'pattern' => '/(?:md5|sha1|sha256|hash)\s*\([^)]+\)\s*(?:===?|!==?|strcmp|==)\s*(?:\$|["\'])/i',
            'severity' => VulnerabilityInterface::SEVERITY_HIGH,
            'description' => 'Direct hash comparison is vulnerable to timing attacks',
            'recommendation' => 'Use password_verify() for passwords or hash_equals() for secure comparison',
        ],
    ];

    public function getName(): string
    {
        return 'Cryptographic Failures Detector';
    }
}
