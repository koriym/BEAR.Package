<?php

declare(strict_types=1);

namespace MyVendor\VulnerableApp\Resource\App;

use BEAR\Resource\ResourceObject;

/**
 * XSS and Command Injection vulnerabilities
 */
class Search extends ResourceObject
{
    /**
     * VULNERABILITY: Cross-Site Scripting (A03)
     * Detectable by: SAST XssDetector
     */
    public function onGet(string $query): static
    {
        // BAD: No escaping
        $this->body = [
            'html' => '<div>Search results for: ' . $_GET['query'] . '</div>',
        ];

        return $this;
    }

    /**
     * VULNERABILITY: Command Injection (A03)
     * Detectable by: SAST CommandInjectionDetector
     */
    public function onPost(string $filename): static
    {
        // BAD: Direct shell execution
        $output = shell_exec('grep -r "' . $filename . '" /var/log/');
        $this->body = ['output' => $output];

        return $this;
    }
}
