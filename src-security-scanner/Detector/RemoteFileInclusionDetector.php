<?php

declare(strict_types=1);

namespace BEAR\SecurityScanner\Detector;

/**
 * Detects Remote File Inclusion (RFI) vulnerabilities
 */
final class RemoteFileInclusionDetector extends AbstractDetector
{
    /** @return array<string, array{pattern: string, severity: string, description: string, recommendation: string}> */
    protected function getPatterns(): array
    {
        return [
            'RFI_INCLUDE_HTTP' => [
                'pattern' => '/\b(include|require|include_once|require_once)\s*\(\s*["\']https?:\/\//i',
                'severity' => 'critical',
                'description' => 'Hardcoded remote URL in include/require statement',
                'recommendation' => 'Never include remote files. Use local files only.',
            ],
            'RFI_INCLUDE_VARIABLE' => [
                'pattern' => '/\b(include|require|include_once|require_once)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/i',
                'severity' => 'critical',
                'description' => 'User input directly used in include/require - allows RFI/LFI',
                'recommendation' => 'Never use user input in include/require. Use a whitelist of allowed files.',
            ],
            'RFI_INCLUDE_CONCAT' => [
                'pattern' => '/\b(include|require|include_once|require_once)\s*\(\s*\$\w+\s*\.\s*\$_(GET|POST|REQUEST|COOKIE)/i',
                'severity' => 'critical',
                'description' => 'User input concatenated in include/require path',
                'recommendation' => 'Never use user input in include paths. Use basename() and whitelist validation.',
            ],
            'RFI_FILE_GET_CONTENTS_URL' => [
                'pattern' => '/file_get_contents\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/i',
                'severity' => 'high',
                'description' => 'User-controlled URL in file_get_contents - potential SSRF/RFI',
                'recommendation' => 'Validate and whitelist allowed URLs. Use cURL with proper configuration.',
            ],
            'RFI_CURL_USER_URL' => [
                'pattern' => '/curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$_(GET|POST|REQUEST|COOKIE)/i',
                'severity' => 'high',
                'description' => 'User-controlled URL in cURL - potential SSRF',
                'recommendation' => 'Validate and whitelist allowed URLs and domains.',
            ],
            'RFI_FOPEN_URL' => [
                'pattern' => '/fopen\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/i',
                'severity' => 'high',
                'description' => 'User-controlled path in fopen - potential RFI if allow_url_fopen is enabled',
                'recommendation' => 'Validate paths and use whitelist. Disable allow_url_fopen if not needed.',
            ],
        ];
    }

    public function getName(): string
    {
        return 'Remote File Inclusion Detector';
    }
}
