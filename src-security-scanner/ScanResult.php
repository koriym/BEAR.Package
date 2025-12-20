<?php

declare(strict_types=1);

namespace BEAR\SecurityScanner;

use function array_filter;
use function array_map;
use function count;
use function round;

/**
 * Represents the complete result of a security scan
 */
final class ScanResult
{
    /** @var VulnerabilityInterface[] */
    private array $vulnerabilities = [];

    private int $filesScanned = 0;
    private float $scanTime = 0.0;

    /**
     * @param VulnerabilityInterface[] $vulnerabilities
     */
    public function __construct(array $vulnerabilities = [], int $filesScanned = 0, float $scanTime = 0.0)
    {
        $this->vulnerabilities = $vulnerabilities;
        $this->filesScanned = $filesScanned;
        $this->scanTime = $scanTime;
    }

    public function addVulnerability(VulnerabilityInterface $vulnerability): void
    {
        $this->vulnerabilities[] = $vulnerability;
    }

    /**
     * @param VulnerabilityInterface[] $vulnerabilities
     */
    public function addVulnerabilities(array $vulnerabilities): void
    {
        foreach ($vulnerabilities as $vulnerability) {
            $this->vulnerabilities[] = $vulnerability;
        }
    }

    public function incrementFilesScanned(): void
    {
        $this->filesScanned++;
    }

    public function setScanTime(float $time): void
    {
        $this->scanTime = $time;
    }

    /**
     * @return VulnerabilityInterface[]
     */
    public function getVulnerabilities(): array
    {
        return $this->vulnerabilities;
    }

    /**
     * @return VulnerabilityInterface[]
     */
    public function getVulnerabilitiesBySeverity(string $severity): array
    {
        return array_filter(
            $this->vulnerabilities,
            static fn (VulnerabilityInterface $v): bool => $v->getSeverity() === $severity
        );
    }

    public function getVulnerabilityCount(): int
    {
        return count($this->vulnerabilities);
    }

    public function getCriticalCount(): int
    {
        return count($this->getVulnerabilitiesBySeverity(VulnerabilityInterface::SEVERITY_CRITICAL));
    }

    public function getHighCount(): int
    {
        return count($this->getVulnerabilitiesBySeverity(VulnerabilityInterface::SEVERITY_HIGH));
    }

    public function getMediumCount(): int
    {
        return count($this->getVulnerabilitiesBySeverity(VulnerabilityInterface::SEVERITY_MEDIUM));
    }

    public function getLowCount(): int
    {
        return count($this->getVulnerabilitiesBySeverity(VulnerabilityInterface::SEVERITY_LOW));
    }

    public function getFilesScanned(): int
    {
        return $this->filesScanned;
    }

    public function getScanTime(): float
    {
        return $this->scanTime;
    }

    public function hasVulnerabilities(): bool
    {
        return count($this->vulnerabilities) > 0;
    }

    public function hasCriticalOrHigh(): bool
    {
        return $this->getCriticalCount() > 0 || $this->getHighCount() > 0;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'summary' => [
                'files_scanned' => $this->filesScanned,
                'scan_time_seconds' => round($this->scanTime, 2),
                'total_vulnerabilities' => $this->getVulnerabilityCount(),
                'critical' => $this->getCriticalCount(),
                'high' => $this->getHighCount(),
                'medium' => $this->getMediumCount(),
                'low' => $this->getLowCount(),
            ],
            'vulnerabilities' => array_map(
                static fn (VulnerabilityInterface $v): array => $v instanceof Vulnerability ? $v->toArray() : [
                    'type' => $v->getType(),
                    'severity' => $v->getSeverity(),
                    'file' => $v->getFile(),
                    'line' => $v->getLine(),
                    'description' => $v->getDescription(),
                ],
                $this->vulnerabilities
            ),
        ];
    }
}
