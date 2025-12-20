<?php

declare(strict_types=1);

namespace BEAR\Security;

/**
 * Interface for vulnerability detectors
 */
interface DetectorInterface
{
    /**
     * Get the detector name
     */
    public function getName(): string;

    /**
     * Scan file content for vulnerabilities
     *
     * @param string $filePath Path to the file being scanned
     * @param string $content  File content to analyze
     *
     * @return VulnerabilityInterface[]
     */
    public function scan(string $filePath, string $content): array;
}
