<?php

declare(strict_types=1);

namespace BEAR\Security\Detector;

use BEAR\Security\VulnerabilityInterface;

/**
 * Detects potential Path/Directory Traversal vulnerabilities
 */
final class PathTraversalDetector extends AbstractDetector
{
    /** @var array<string, array{pattern: string, severity: string, description: string, recommendation: string}> */
    protected array $patterns = [
        'PATH_TRAVERSAL_FILE_OPS' => [
            'pattern' => '/\b(?:file_get_contents|file_put_contents|fopen|readfile|file|include|require|include_once|require_once)\s*\([^)]*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'User input used directly in file operation - path traversal vulnerability',
            'recommendation' => 'Validate and sanitize file paths; use basename() and realpath() to prevent directory traversal',
        ],
        'PATH_TRAVERSAL_CONCAT' => [
            'pattern' => '/\b(?:file_get_contents|file_put_contents|fopen|readfile|file|include|require)\s*\([^)]*\.\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'User input concatenated in file path',
            'recommendation' => 'Use whitelist of allowed files/directories and validate with realpath()',
        ],
        'PATH_TRAVERSAL_UNLINK' => [
            'pattern' => '/\b(?:unlink|rmdir|rename|copy|move_uploaded_file)\s*\([^)]*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[/i',
            'severity' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'description' => 'User input in file deletion/manipulation operation',
            'recommendation' => 'Strictly validate file paths and ensure they are within allowed directories',
        ],
        'PATH_TRAVERSAL_MKDIR' => [
            'pattern' => '/\bmkdir\s*\([^)]*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[/i',
            'severity' => VulnerabilityInterface::SEVERITY_HIGH,
            'description' => 'User input used in directory creation',
            'recommendation' => 'Validate directory names and prevent special characters like ../',
        ],
        'PATH_TRAVERSAL_GLOB' => [
            'pattern' => '/\bglob\s*\([^)]*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[/i',
            'severity' => VulnerabilityInterface::SEVERITY_HIGH,
            'description' => 'User input in glob pattern - information disclosure risk',
            'recommendation' => 'Sanitize glob patterns and restrict to allowed directories',
        ],
        'PATH_TRAVERSAL_SCANDIR' => [
            'pattern' => '/\b(?:scandir|opendir|readdir)\s*\([^)]*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[/i',
            'severity' => VulnerabilityInterface::SEVERITY_HIGH,
            'description' => 'User input in directory listing function',
            'recommendation' => 'Validate and restrict directory access to allowed paths',
        ],
        'LFI_INCLUDE_VARIABLE' => [
            'pattern' => '/\b(?:include|require|include_once|require_once)\s*\(\s*\$[a-zA-Z_]\w*\s*\)/i',
            'severity' => VulnerabilityInterface::SEVERITY_MEDIUM,
            'description' => 'Variable used in include/require - verify it is not user-controlled',
            'recommendation' => 'Use a whitelist of allowed files for dynamic includes',
        ],
        'PATH_TRAVERSAL_ZIP' => [
            'pattern' => '/\b(?:ZipArchive|PharData)\s*->\s*(?:open|extractTo)\s*\([^)]*\$(?:_GET|_POST|_REQUEST|_COOKIE)/i',
            'severity' => VulnerabilityInterface::SEVERITY_HIGH,
            'description' => 'User input in archive extraction - zip slip vulnerability',
            'recommendation' => 'Validate extracted file paths and ensure they stay within target directory',
        ],
    ];

    public function getName(): string
    {
        return 'Path Traversal Detector';
    }
}
