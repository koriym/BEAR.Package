<?php

declare(strict_types=1);

namespace BEAR\Security\Output;

use BEAR\Security\ScanResult;

/**
 * Interface for scan result output formatters
 */
interface OutputInterface
{
    /**
     * Format and return the scan result
     */
    public function format(ScanResult $result): string;
}
