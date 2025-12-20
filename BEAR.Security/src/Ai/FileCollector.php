<?php

declare(strict_types=1);

namespace BEAR\Security\Ai;

use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

use function file_get_contents;
use function in_array;
use function pathinfo;
use function preg_match;

use const PATHINFO_EXTENSION;

/**
 * Collects PHP files for AI analysis
 */
final class FileCollector
{
    /** @var string[] */
    private array $extensions = ['php', 'phtml'];

    /** @var string[] */
    private array $excludePatterns = [
        '#/vendor/#',
        '#/node_modules/#',
        '#/\.git/#',
        '#/var/cache/#',
        '#/var/tmp/#',
    ];

    /**
     * Collect files from directory
     *
     * @return array<string, string> File path => content
     */
    public function collect(string $directory): array
    {
        $files = [];

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory),
        );

        /** @var SplFileInfo $file */
        foreach ($iterator as $file) {
            if (! $file->isFile()) {
                continue;
            }

            $path = $file->getPathname();

            if (! $this->shouldInclude($path)) {
                continue;
            }

            $content = file_get_contents($path);
            if ($content !== false) {
                $files[$path] = $content;
            }
        }

        return $files;
    }

    /**
     * Set file extensions to include
     *
     * @param string[] $extensions
     */
    public function setExtensions(array $extensions): self
    {
        $this->extensions = $extensions;

        return $this;
    }

    /**
     * Add exclude pattern
     */
    public function addExcludePattern(string $pattern): self
    {
        $this->excludePatterns[] = $pattern;

        return $this;
    }

    private function shouldInclude(string $path): bool
    {
        $ext = pathinfo($path, PATHINFO_EXTENSION);
        if (! in_array($ext, $this->extensions, true)) {
            return false;
        }

        foreach ($this->excludePatterns as $pattern) {
            if (preg_match($pattern, $path)) {
                return false;
            }
        }

        return true;
    }
}
