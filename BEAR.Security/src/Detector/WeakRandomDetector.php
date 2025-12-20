<?php

declare(strict_types=1);

namespace BEAR\Security\Detector;

/**
 * Detects weak random number generation for security purposes
 */
final class WeakRandomDetector extends AbstractDetector
{
    /** @var array<string, array{pattern: string, severity: string, description: string, recommendation: string}> */
    protected array $patterns = [
        'WEAK_RANDOM_TOKEN' => [
            'pattern' => '/(token|secret|key|password|session|csrf|nonce)\s*=\s*(md5|sha1)\s*\(\s*(time|microtime|rand|mt_rand)\s*\(/i',
            'severity' => 'HIGH',
            'description' => 'Predictable token generation using weak random source',
            'recommendation' => 'Use random_bytes() or random_int() for cryptographic randomness',
        ],
        'WEAK_RANDOM_RAND' => [
            'pattern' => '/(token|secret|key|nonce|csrf)\s*=\s*rand\s*\(/i',
            'severity' => 'HIGH',
            'description' => 'Using rand() for security-sensitive value',
            'recommendation' => 'Use random_int() instead of rand() for security purposes',
        ],
        'WEAK_RANDOM_MT_RAND' => [
            'pattern' => '/(token|secret|key|nonce|csrf)\s*=\s*mt_rand\s*\(/i',
            'severity' => 'HIGH',
            'description' => 'Using mt_rand() for security-sensitive value',
            'recommendation' => 'Use random_int() instead of mt_rand() for security purposes',
        ],
        'WEAK_RANDOM_UNIQID' => [
            'pattern' => '/(token|secret|session|csrf)\s*=\s*uniqid\s*\(/i',
            'severity' => 'MEDIUM',
            'description' => 'uniqid() is not cryptographically secure',
            'recommendation' => 'Use bin2hex(random_bytes(16)) for secure unique identifiers',
        ],
        'WEAK_RANDOM_TIME_BASED' => [
            'pattern' => '/(token|secret|key)\s*=\s*(md5|sha1)\s*\(\s*\(string\)\s*time\s*\(\)/i',
            'severity' => 'CRITICAL',
            'description' => 'Token based on time() is completely predictable',
            'recommendation' => 'Use bin2hex(random_bytes(32)) for secure tokens',
        ],
        'WEAK_RANDOM_SHUFFLE' => [
            'pattern' => '/shuffle\s*\([^)]*\).*\b(password|token|key)\b/i',
            'severity' => 'MEDIUM',
            'description' => 'shuffle() uses weak randomness for password/token generation',
            'recommendation' => 'Use random_int() with Fisher-Yates shuffle for secure shuffling',
        ],
    ];

    public function getName(): string
    {
        return 'WeakRandomDetector';
    }
}
