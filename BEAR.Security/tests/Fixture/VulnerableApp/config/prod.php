<?php

declare(strict_types=1);

/**
 * VULNERABILITY: Hardcoded secrets in config (A02)
 * Detectable by: SAST CryptographicFailuresDetector
 */
return [
    'database' => [
        'host' => 'db.example.com',
        'user' => 'admin',
        'password' => 'ProductionP@ssw0rd!',  // BAD: Hardcoded
    ],
    'aws' => [
        'access_key' => 'AKIAIOSFODNN7EXAMPLE',  // BAD: Hardcoded AWS key
        'secret_key' => 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    ],
    'api' => [
        'stripe_key' => 'sk_live_51abc123def456',  // BAD: Hardcoded
    ],
];
