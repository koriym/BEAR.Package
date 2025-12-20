<?php

declare(strict_types=1);

namespace BEAR\Security\Ai;

/**
 * Interface for AI-powered security auditor
 */
interface AuditorInterface
{
    /**
     * Audit a project for security vulnerabilities
     *
     * @param string $projectPath Path to the project root
     */
    public function audit(string $projectPath): AuditResult;
}
