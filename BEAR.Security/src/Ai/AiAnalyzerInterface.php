<?php

declare(strict_types=1);

namespace BEAR\Security\Ai;

use BEAR\Security\Vulnerability;

/**
 * Interface for AI-powered security analysis
 */
interface AiAnalyzerInterface
{
    /**
     * Analyze a file for security vulnerabilities
     *
     * @return list<Vulnerability>
     */
    public function analyzeFile(string $filePath, string $content): array;

    /**
     * Get token tracker for usage statistics
     */
    public function getTokenTracker(): TokenTracker;
}
