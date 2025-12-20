<?php

declare(strict_types=1);

namespace BEAR\SecurityScanner\Output;

use BEAR\SecurityScanner\ScanResult;

use function json_encode;

use const JSON_PRETTY_PRINT;
use const JSON_UNESCAPED_SLASHES;

/**
 * JSON output formatter
 */
final class JsonOutput implements OutputInterface
{
    private bool $prettyPrint;

    public function __construct(bool $prettyPrint = true)
    {
        $this->prettyPrint = $prettyPrint;
    }

    public function format(ScanResult $result): string
    {
        $flags = JSON_UNESCAPED_SLASHES;

        if ($this->prettyPrint) {
            $flags |= JSON_PRETTY_PRINT;
        }

        $json = json_encode($result->toArray(), $flags);

        return $json === false ? '{}' : $json;
    }
}
