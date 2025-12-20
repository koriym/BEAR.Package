<?php

declare(strict_types=1);

namespace BEAR\Security\Output;

use BEAR\Security\ScanResult;

use function json_encode;

use const JSON_PRETTY_PRINT;
use const JSON_UNESCAPED_SLASHES;

/**
 * JSON output formatter
 */
final class JsonOutput implements OutputInterface
{
    public function __construct(private bool $prettyPrint = true)
    {
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
