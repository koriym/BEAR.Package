<?php

declare(strict_types=1);

namespace BEAR\SecurityScanner\Dast\Payload;

/**
 * Interface for attack payloads used in DAST scanning
 */
interface PayloadInterface
{
    /**
     * Get the payload name/type
     */
    public function getName(): string;

    /**
     * Get all payloads for this attack type
     *
     * @return string[]
     */
    public function getPayloads(): array;

    /**
     * Get patterns that indicate a successful attack (vulnerability detected)
     *
     * @return string[]
     */
    public function getSuccessPatterns(): array;

    /**
     * Get the severity level of this vulnerability type
     */
    public function getSeverity(): string;

    /**
     * Get description of this vulnerability type
     */
    public function getDescription(): string;

    /**
     * Get recommendation for fixing this vulnerability
     */
    public function getRecommendation(): string;
}
