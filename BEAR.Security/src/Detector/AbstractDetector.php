<?php

declare(strict_types=1);

namespace BEAR\Security\Detector;

use BEAR\Security\DetectorInterface;
use BEAR\Security\Vulnerability;

use function array_slice;
use function count;
use function explode;
use function implode;
use function max;
use function min;
use function preg_match_all;
use function substr;
use function substr_count;
use function trim;

use const PREG_OFFSET_CAPTURE;

/**
 * Abstract base class for vulnerability detectors
 */
abstract class AbstractDetector implements DetectorInterface
{
    /** @var array<string, array{pattern: string, severity: string, description: string, recommendation: string}> */
    protected array $patterns = [];

    abstract public function getName(): string;

    /**
     * {@inheritDoc}
     */
    public function scan(string $filePath, string $content): array
    {
        $vulnerabilities = [];

        foreach ($this->patterns as $type => $config) {
            $matches = $this->findMatches($content, $config['pattern']);
            foreach ($matches as $match) {
                $vulnerabilities[] = new Vulnerability(
                    $type,
                    $config['severity'],
                    $filePath,
                    $match['line'],
                    $config['description'],
                    $match['code'],
                    $config['recommendation'],
                );
            }
        }

        return $vulnerabilities;
    }

    /**
     * Find all pattern matches in content
     *
     * @return array<int, array{line: int, code: string}>
     */
    protected function findMatches(string $content, string $pattern): array
    {
        $matches = [];
        $result = preg_match_all($pattern, $content, $found, PREG_OFFSET_CAPTURE);

        if ($result === false || $result === 0) {
            return [];
        }

        $lines = explode("\n", $content);

        foreach ($found[0] as $match) {
            $offset = $match[1];
            $lineNumber = $this->getLineNumber($content, $offset);
            $codeSnippet = $this->getCodeSnippet($lines, $lineNumber);

            $matches[] = [
                'line' => $lineNumber,
                'code' => $codeSnippet,
            ];
        }

        return $matches;
    }

    /**
     * Get line number from character offset
     */
    protected function getLineNumber(string $content, int $offset): int
    {
        $substring = substr($content, 0, $offset);

        return substr_count($substring, "\n") + 1;
    }

    /**
     * Get code snippet around the given line
     *
     * @param string[] $lines
     */
    protected function getCodeSnippet(array $lines, int $lineNumber, int $context = 2): string
    {
        $start = max(0, $lineNumber - $context - 1);
        $length = min(count($lines) - $start, $context * 2 + 1);
        $snippet = array_slice($lines, $start, $length);

        return trim(implode("\n", $snippet));
    }
}
