<?php

declare(strict_types=1);

namespace BEAR\Security;

use BEAR\Security\Detector\CommandInjectionDetector;
use BEAR\Security\Detector\CryptographicFailuresDetector;
use BEAR\Security\Detector\CsrfDetector;
use BEAR\Security\Detector\DangerousFunctionDetector;
use BEAR\Security\Detector\InsecureDeserializationDetector;
use BEAR\Security\Detector\PathTraversalDetector;
use BEAR\Security\Detector\RemoteFileInclusionDetector;
use BEAR\Security\Detector\SessionSecurityDetector;
use BEAR\Security\Detector\SqlInjectionDetector;
use BEAR\Security\Detector\XssDetector;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

use function file_get_contents;
use function in_array;
use function microtime;
use function pathinfo;
use function preg_match;

use const PATHINFO_EXTENSION;

/**
 * Main security scanner class
 */
final class Scanner
{
    /** @var DetectorInterface[] */
    private array $detectors;

    /** @var string[] */
    private array $excludePatterns = [];

    /** @var string[] */
    private array $includeExtensions = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps'];

    /** @param DetectorInterface[]|null $detectors Custom detectors or null for defaults */
    public function __construct(array|null $detectors = null)
    {
        $this->detectors = $detectors ?? $this->getDefaultDetectors();
    }

    /** @return DetectorInterface[] */
    private function getDefaultDetectors(): array
    {
        return [
            new SqlInjectionDetector(),
            new XssDetector(),
            new CommandInjectionDetector(),
            new PathTraversalDetector(),
            new RemoteFileInclusionDetector(),
            new CsrfDetector(),
            new CryptographicFailuresDetector(),
            new InsecureDeserializationDetector(),
            new DangerousFunctionDetector(),
            new SessionSecurityDetector(),
        ];
    }

    /**
     * Set patterns to exclude from scanning
     *
     * @param string[] $patterns Regex patterns to exclude
     */
    public function setExcludePatterns(array $patterns): self
    {
        $this->excludePatterns = $patterns;

        return $this;
    }

    /**
     * Set file extensions to include
     *
     * @param string[] $extensions File extensions without dot
     */
    public function setIncludeExtensions(array $extensions): self
    {
        $this->includeExtensions = $extensions;

        return $this;
    }

    /**
     * Add a custom detector
     */
    public function addDetector(DetectorInterface $detector): self
    {
        $this->detectors[] = $detector;

        return $this;
    }

    /**
     * Scan a directory for vulnerabilities
     */
    public function scanDirectory(string $directory): ScanResult
    {
        $startTime = microtime(true);
        $result = new ScanResult();

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory),
        );

        /** @var SplFileInfo $file */
        foreach ($iterator as $file) {
            if (! $file->isFile()) {
                continue;
            }

            $filePath = $file->getPathname();

            if (! $this->shouldScanFile($filePath)) {
                continue;
            }

            $vulnerabilities = $this->scanFile($filePath);
            $result->addVulnerabilities($vulnerabilities);
            $result->incrementFilesScanned();
        }

        $result->setScanTime(microtime(true) - $startTime);

        return $result;
    }

    /**
     * Scan a single file for vulnerabilities
     *
     * @return VulnerabilityInterface[]
     */
    public function scanFile(string $filePath): array
    {
        $content = file_get_contents($filePath);

        if ($content === false) {
            return [];
        }

        $vulnerabilities = [];

        foreach ($this->detectors as $detector) {
            $found = $detector->scan($filePath, $content);
            foreach ($found as $vulnerability) {
                $vulnerabilities[] = $vulnerability;
            }
        }

        return $vulnerabilities;
    }

    /**
     * Check if a file should be scanned
     */
    private function shouldScanFile(string $filePath): bool
    {
        // Check extension
        $extension = pathinfo($filePath, PATHINFO_EXTENSION);
        if (! in_array($extension, $this->includeExtensions, true)) {
            return false;
        }

        // Check exclude patterns
        foreach ($this->excludePatterns as $pattern) {
            if (preg_match($pattern, $filePath)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Get list of registered detectors
     *
     * @return DetectorInterface[]
     */
    public function getDetectors(): array
    {
        return $this->detectors;
    }
}
