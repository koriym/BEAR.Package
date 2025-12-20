<?php

declare(strict_types=1);

namespace BEAR\Security\Output;

use BEAR\Security\ScanResult;
use BEAR\Security\VulnerabilityInterface;

use function explode;
use function sprintf;
use function str_repeat;
use function strtoupper;

use const PHP_EOL;

/**
 * Console output formatter with colors
 */
final class ConsoleOutput implements OutputInterface
{
    private const COLOR_RESET = "\033[0m";
    private const COLOR_RED = "\033[31m";
    private const COLOR_YELLOW = "\033[33m";
    private const COLOR_GREEN = "\033[32m";
    private const COLOR_CYAN = "\033[36m";
    private const COLOR_WHITE = "\033[37m";
    private const COLOR_BOLD = "\033[1m";

    public function __construct(private bool $useColors = true)
    {
    }

    public function format(ScanResult $result): string
    {
        $output = '';

        // Header
        $output .= $this->line('=', 70) . PHP_EOL;
        $output .= $this->bold('  BEAR Security Scanner - Scan Results') . PHP_EOL;
        $output .= $this->line('=', 70) . PHP_EOL . PHP_EOL;

        // Summary
        $output .= $this->formatSummary($result);

        // Vulnerabilities
        if ($result->hasVulnerabilities()) {
            $output .= $this->formatVulnerabilities($result);
        } else {
            $output .= $this->color(PHP_EOL . '  No vulnerabilities found!' . PHP_EOL, self::COLOR_GREEN);
        }

        // Footer
        $output .= PHP_EOL . $this->line('=', 70) . PHP_EOL;

        return $output;
    }

    private function formatSummary(ScanResult $result): string
    {
        $output = $this->bold('  Summary:') . PHP_EOL;
        $output .= $this->line('-', 40) . PHP_EOL;
        $output .= sprintf("  Files scanned:     %d\n", $result->getFilesScanned());
        $output .= sprintf("  Scan time:         %.2f seconds\n", $result->getScanTime());
        $output .= sprintf("  Total issues:      %d\n", $result->getVulnerabilityCount());
        $output .= PHP_EOL;

        if ($result->hasVulnerabilities()) {
            $output .= $this->bold('  By Severity:') . PHP_EOL;

            $critical = $result->getCriticalCount();
            $high = $result->getHighCount();
            $medium = $result->getMediumCount();
            $low = $result->getLowCount();

            if ($critical > 0) {
                $output .= $this->color(sprintf("    CRITICAL: %d\n", $critical), self::COLOR_RED);
            }

            if ($high > 0) {
                $output .= $this->color(sprintf("    HIGH:     %d\n", $high), self::COLOR_RED);
            }

            if ($medium > 0) {
                $output .= $this->color(sprintf("    MEDIUM:   %d\n", $medium), self::COLOR_YELLOW);
            }

            if ($low > 0) {
                $output .= $this->color(sprintf("    LOW:      %d\n", $low), self::COLOR_WHITE);
            }
        }

        return $output;
    }

    private function formatVulnerabilities(ScanResult $result): string
    {
        $output = PHP_EOL . $this->bold('  Vulnerabilities:') . PHP_EOL;
        $output .= $this->line('-', 70) . PHP_EOL;

        $severityOrder = [
            VulnerabilityInterface::SEVERITY_CRITICAL,
            VulnerabilityInterface::SEVERITY_HIGH,
            VulnerabilityInterface::SEVERITY_MEDIUM,
            VulnerabilityInterface::SEVERITY_LOW,
        ];

        $index = 1;
        foreach ($severityOrder as $severity) {
            $vulnerabilities = $result->getVulnerabilitiesBySeverity($severity);
            foreach ($vulnerabilities as $vuln) {
                $output .= $this->formatVulnerability($vuln, $index++);
            }
        }

        return $output;
    }

    private function formatVulnerability(VulnerabilityInterface $vuln, int $index): string
    {
        $severityColor = $this->getSeverityColor($vuln->getSeverity());

        $output = PHP_EOL;
        $output .= sprintf('  [%d] ', $index);
        $output .= $this->color(
            sprintf('[%s]', strtoupper($vuln->getSeverity())),
            $severityColor,
        );
        $output .= sprintf(" %s\n", $vuln->getType());
        $output .= sprintf("      File: %s:%d\n", $vuln->getFile(), $vuln->getLine());
        $output .= sprintf("      Description: %s\n", $vuln->getDescription());
        $output .= $this->color(
            sprintf("      Recommendation: %s\n", $vuln->getRecommendation()),
            self::COLOR_CYAN,
        );

        $snippet = $vuln->getCodeSnippet();
        if ($snippet !== '') {
            $output .= "      Code:\n";
            foreach (explode("\n", $snippet) as $line) {
                $output .= sprintf("        %s\n", $line);
            }
        }

        return $output;
    }

    private function getSeverityColor(string $severity): string
    {
        return match ($severity) {
            VulnerabilityInterface::SEVERITY_CRITICAL,
            VulnerabilityInterface::SEVERITY_HIGH => self::COLOR_RED,
            VulnerabilityInterface::SEVERITY_MEDIUM => self::COLOR_YELLOW,
            default => self::COLOR_WHITE,
        };
    }

    private function color(string $text, string $color): string
    {
        if (! $this->useColors) {
            return $text;
        }

        return $color . $text . self::COLOR_RESET;
    }

    private function bold(string $text): string
    {
        if (! $this->useColors) {
            return $text;
        }

        return self::COLOR_BOLD . $text . self::COLOR_RESET;
    }

    private function line(string $char, int $length): string
    {
        return '  ' . str_repeat($char, $length);
    }
}
