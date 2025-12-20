<?php

declare(strict_types=1);

namespace BEAR\Security\Ai;

/**
 * Interface for AI-powered security analysis
 */
interface AiAnalyzerInterface
{
    /**
     * Analyze a project for security vulnerabilities
     *
     * @param string $projectPath Path to the project root
     */
    public function analyze(string $projectPath): AiAnalysisResult;
}
