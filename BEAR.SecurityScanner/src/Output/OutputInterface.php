<?php

declare(strict_types=1);

namespace BEAR\SecurityScanner\Output;

use BEAR\SecurityScanner\ScanResult;

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
