<?php

declare(strict_types=1);

namespace BEAR\Security\Analyzer;

use BEAR\Security\ScanResult;
use BEAR\Security\Vulnerability;
use BEAR\Security\VulnerabilityInterface;

use function escapeshellarg;
use function exec;
use function file_exists;
use function implode;
use function is_array;
use function is_string;
use function json_decode;
use function sprintf;

/**
 * Scans for vulnerable dependencies using composer audit (OWASP A06)
 */
final class ComposerAuditScanner
{
    /**
     * Scan a project directory for vulnerable dependencies
     *
     * @param string $directory Project directory containing composer.lock
     */
    public function scan(string $directory): ScanResult
    {
        $result = new ScanResult();
        $lockFile = $directory . '/composer.lock';

        if (! file_exists($lockFile)) {
            return $result;
        }

        $vulnerabilities = $this->runComposerAudit($directory);
        $result->addVulnerabilities($vulnerabilities);

        return $result;
    }

    /**
     * Run composer audit and parse results
     *
     * @return VulnerabilityInterface[]
     */
    private function runComposerAudit(string $directory): array
    {
        $output = [];
        $returnCode = 0;

        exec(
            sprintf('cd %s && composer audit --format=json 2>/dev/null', escapeshellarg($directory)),
            $output,
            $returnCode,
        );

        if ($output === []) {
            return [];
        }

        $json = implode("\n", $output);
        $data = json_decode($json, true);

        if (! is_array($data) || ! isset($data['advisories']) || ! is_array($data['advisories'])) {
            return [];
        }

        return $this->parseAdvisories($data['advisories']);
    }

    /**
     * Parse advisories from composer audit output
     *
     * @param array<string|int, mixed> $advisories
     *
     * @return VulnerabilityInterface[]
     */
    private function parseAdvisories(array $advisories): array
    {
        $vulnerabilities = [];

        foreach ($advisories as $packageName => $packageAdvisories) {
            if (! is_string($packageName) || ! is_array($packageAdvisories)) {
                continue;
            }

            foreach ($packageAdvisories as $advisory) {
                if (! is_array($advisory)) {
                    continue;
                }

                $typedAdvisory = $advisory;
                /** @var array<string, mixed> $typedAdvisory */
                $vulnerabilities[] = $this->createVulnerability($packageName, $typedAdvisory);
            }
        }

        return $vulnerabilities;
    }

    /**
     * Create vulnerability from advisory data
     *
     * @param array<string, mixed> $advisory
     */
    private function createVulnerability(string $packageName, array $advisory): VulnerabilityInterface
    {
        $severityRaw = $advisory['severity'] ?? 'unknown';
        $severity = $this->mapSeverity(is_string($severityRaw) ? $severityRaw : 'unknown');

        $title = isset($advisory['title']) && is_string($advisory['title'])
            ? $advisory['title']
            : 'Unknown vulnerability';

        $advisoryId = isset($advisory['advisoryId']) && is_string($advisory['advisoryId'])
            ? $advisory['advisoryId']
            : (isset($advisory['cve']) && is_string($advisory['cve']) ? $advisory['cve'] : 'Unknown');

        $affectedVersions = isset($advisory['affectedVersions']) && is_string($advisory['affectedVersions'])
            ? $advisory['affectedVersions']
            : 'unknown';

        $link = isset($advisory['link']) && is_string($advisory['link'])
            ? $advisory['link']
            : '';

        $description = sprintf('%s (Affected: %s)', $title, $affectedVersions);

        $recommendation = $link !== ''
            ? sprintf('Update %s to a patched version. See: %s', $packageName, $link)
            : sprintf('Update %s to a patched version', $packageName);

        return new Vulnerability(
            'VULNERABLE_DEPENDENCY',
            $severity,
            sprintf('composer.lock (%s)', $packageName),
            0,
            $description,
            sprintf('%s: %s', $advisoryId, $title),
            $recommendation,
        );
    }

    /**
     * Map composer audit severity to our severity levels
     */
    private function mapSeverity(string $severity): string
    {
        return match ($severity) {
            'critical' => VulnerabilityInterface::SEVERITY_CRITICAL,
            'high' => VulnerabilityInterface::SEVERITY_HIGH,
            'medium' => VulnerabilityInterface::SEVERITY_MEDIUM,
            'low' => VulnerabilityInterface::SEVERITY_LOW,
            default => VulnerabilityInterface::SEVERITY_MEDIUM,
        };
    }
}
