<?php

declare(strict_types=1);

namespace MyVendor\VulnerableApp\Resource\App;

use BEAR\Resource\ResourceObject;

/**
 * Miscellaneous vulnerabilities often missed by scanners
 */
class Misc extends ResourceObject
{
    /**
     * VULNERABILITY: Open Redirect (A01)
     * Often missed - requires understanding URL validation
     */
    public function onGet(string $next): static
    {
        // BAD: No validation of redirect target
        header('Location: ' . $_GET['next']);
        exit;
    }

    /**
     * VULNERABILITY: Log Injection
     * Attacker can inject fake log entries or break log format
     */
    public function onPost(string $action): static
    {
        // BAD: User input directly in logs
        error_log("User performed action: " . $_POST['action']);

        return $this;
    }

    /**
     * VULNERABILITY: XML External Entity (XXE) - A05
     * Can read local files or perform SSRF
     */
    public function onPut(string $xml): static
    {
        // BAD: External entities enabled by default in older PHP
        $doc = simplexml_load_string($_POST['xml']);
        $this->body = ['result' => (array) $doc];

        return $this;
    }

    /**
     * VULNERABILITY: ReDoS - Regular Expression Denial of Service
     * Catastrophic backtracking with malicious input
     */
    public function validateEmail(string $email): bool
    {
        // BAD: Evil regex - exponential time with crafted input
        // Input like "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!" causes DoS
        return (bool) preg_match('/^([a-zA-Z0-9]+)+@[a-zA-Z0-9]+\.[a-zA-Z]+$/', $email);
    }

    /**
     * VULNERABILITY: HTTP Response Splitting / Header Injection
     * Can inject additional headers or content
     */
    public function setCookie(string $value): void
    {
        // BAD: User input in header without newline filtering
        header('Set-Cookie: preference=' . $_GET['value']);
    }

    /**
     * VULNERABILITY: Insufficient Entropy
     * Predictable tokens
     */
    public function generateToken(): string
    {
        // BAD: Predictable - based on time
        return md5((string) time());
    }

    /**
     * VULNERABILITY: Information Disclosure via Error
     * Stack traces expose internal paths and logic
     */
    public function debug(): void
    {
        // BAD: Exposes sensitive information
        ini_set('display_errors', '1');
        error_reporting(E_ALL);
    }
}
