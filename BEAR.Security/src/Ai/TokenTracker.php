<?php

declare(strict_types=1);

namespace BEAR\Security\Ai;

use function number_format;
use function sprintf;

/**
 * Tracks token usage for AI-powered analysis
 */
final class TokenTracker
{
    private int $inputTokens = 0;
    private int $outputTokens = 0;

    /** @var array<string, array{input: int, output: int}> */
    private array $perFile = [];

    /**
     * Record tokens used for a file analysis
     */
    public function record(string $file, int $inputTokens, int $outputTokens): void
    {
        $this->inputTokens += $inputTokens;
        $this->outputTokens += $outputTokens;
        $this->perFile[$file] = [
            'input' => $inputTokens,
            'output' => $outputTokens,
        ];
    }

    /**
     * Get total input tokens
     */
    public function getInputTokens(): int
    {
        return $this->inputTokens;
    }

    /**
     * Get total output tokens
     */
    public function getOutputTokens(): int
    {
        return $this->outputTokens;
    }

    /**
     * Get total tokens (input + output)
     */
    public function getTotalTokens(): int
    {
        return $this->inputTokens + $this->outputTokens;
    }

    /**
     * Get per-file token usage
     *
     * @return array<string, array{input: int, output: int}>
     */
    public function getPerFileUsage(): array
    {
        return $this->perFile;
    }

    /**
     * Get estimated cost in USD (based on Claude API pricing)
     *
     * @param float $inputCostPer1k  Cost per 1K input tokens (default: $0.003 for Claude Sonnet)
     * @param float $outputCostPer1k Cost per 1K output tokens (default: $0.015 for Claude Sonnet)
     */
    public function getEstimatedCost(float $inputCostPer1k = 0.003, float $outputCostPer1k = 0.015): float
    {
        return ($this->inputTokens / 1000 * $inputCostPer1k)
            + ($this->outputTokens / 1000 * $outputCostPer1k);
    }

    /**
     * Get formatted summary
     */
    public function getSummary(): string
    {
        return sprintf(
            "Token Usage:\n  Input:  %s tokens\n  Output: %s tokens\n  Total:  %s tokens\n  Est. Cost: $%.4f",
            number_format($this->inputTokens),
            number_format($this->outputTokens),
            number_format($this->getTotalTokens()),
            $this->getEstimatedCost(),
        );
    }

    /**
     * Reset tracker
     */
    public function reset(): void
    {
        $this->inputTokens = 0;
        $this->outputTokens = 0;
        $this->perFile = [];
    }
}
