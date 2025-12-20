<?php

declare(strict_types=1);

namespace BEAR\Security\Ai;

use RuntimeException;

use function array_filter;
use function count;
use function dirname;
use function file_exists;
use function file_get_contents;
use function glob;
use function is_dir;
use function json_decode;
use function json_encode;
use function preg_match;
use function sprintf;
use function str_replace;

use const GLOB_NOSORT;
use const JSON_PRETTY_PRINT;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_UNICODE;

/**
 * Prompt builder for AI security audit
 */
final class PromptBuilder
{
    private string $skillPath;

    public function __construct(?string $skillPath = null)
    {
        $this->skillPath = $skillPath ?? dirname(__DIR__, 2) . '/SKILL.md';
    }

    /**
     * Build the audit prompt with skill context and files
     *
     * @param array<string, string> $files File path => content
     */
    public function build(array $files): string
    {
        $skill = $this->loadSkill();
        $filesSection = $this->formatFiles($files);

        return <<<PROMPT
You are a security auditor. Use the following SKILL documentation to analyze the provided PHP files.

## SKILL DOCUMENTATION

{$skill}

## FILES TO ANALYZE

{$filesSection}

## INSTRUCTIONS

1. Apply SAST patterns from the SKILL documentation
2. Apply AI-only detection patterns (IDOR, Mass Assignment, Race Condition, etc.)
3. Apply false positive recognition rules
4. Output findings as valid JSON

## OUTPUT FORMAT

Return ONLY valid JSON in this exact format:
```json
{
  "scan_result": {
    "files_scanned": 5,
    "vulnerabilities_found": 10,
    "false_positives_avoided": 3
  },
  "vulnerabilities": [
    {
      "file": "src/User.php",
      "line": 28,
      "type": "SQL_INJECTION",
      "severity": "CRITICAL",
      "detection": "SAST",
      "description": "Direct SQL concatenation",
      "code": "query(\"SELECT * FROM users WHERE id = \" . \$id)"
    }
  ],
  "false_positives": [
    {
      "file": "src/Safe.php",
      "line": 30,
      "pattern": "SQL with variable",
      "reason": "Uses prepared statement"
    }
  ]
}
```

Return ONLY the JSON, no markdown code blocks or explanations.
PROMPT;
    }

    private function loadSkill(): string
    {
        if (! file_exists($this->skillPath)) {
            throw new RuntimeException(sprintf('SKILL.md not found: %s', $this->skillPath));
        }

        $content = file_get_contents($this->skillPath);
        if ($content === false) {
            throw new RuntimeException('Failed to read SKILL.md');
        }

        return $content;
    }

    /**
     * @param array<string, string> $files
     */
    private function formatFiles(array $files): string
    {
        $sections = [];
        foreach ($files as $path => $content) {
            $sections[] = "### {$path}\n```php\n{$content}\n```";
        }

        return implode("\n\n", $sections);
    }

    /**
     * Parse AI response JSON
     *
     * @return array{scan_result: array{files_scanned: int, vulnerabilities_found: int}, vulnerabilities: list<array{file: string, line: int, type: string, severity: string, detection: string, description: string}>}
     */
    public function parseResponse(string $response): array
    {
        // Extract JSON from response (handle markdown code blocks)
        if (preg_match('/```json\s*(.*?)\s*```/s', $response, $matches)) {
            $response = $matches[1];
        } elseif (preg_match('/```\s*(.*?)\s*```/s', $response, $matches)) {
            $response = $matches[1];
        }

        $response = str_replace(["\r\n", "\r"], "\n", $response);

        try {
            /** @var array{scan_result: array{files_scanned: int, vulnerabilities_found: int}, vulnerabilities: list<array{file: string, line: int, type: string, severity: string, detection: string, description: string}>} */
            return json_decode($response, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new RuntimeException('Failed to parse AI response as JSON: ' . $e->getMessage());
        }
    }
}
