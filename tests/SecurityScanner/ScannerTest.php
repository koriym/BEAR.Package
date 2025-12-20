<?php

declare(strict_types=1);

namespace BEAR\Package\SecurityScanner;

use BEAR\SecurityScanner\Detector\CommandInjectionDetector;
use BEAR\SecurityScanner\Detector\DangerousFunctionDetector;
use BEAR\SecurityScanner\Detector\PathTraversalDetector;
use BEAR\SecurityScanner\Detector\SessionSecurityDetector;
use BEAR\SecurityScanner\Detector\SqlInjectionDetector;
use BEAR\SecurityScanner\Detector\XssDetector;
use BEAR\SecurityScanner\Output\ConsoleOutput;
use BEAR\SecurityScanner\Output\JsonOutput;
use BEAR\SecurityScanner\Scanner;
use BEAR\SecurityScanner\ScanResult;
use BEAR\SecurityScanner\VulnerabilityInterface;
use PHPUnit\Framework\TestCase;

use function count;
use function file_get_contents;
use function json_decode;

class ScannerTest extends TestCase
{
    private Scanner $scanner;

    protected function setUp(): void
    {
        $this->scanner = new Scanner();
    }

    public function testScannerCreatesDefaultDetectors(): void
    {
        $detectors = $this->scanner->getDetectors();
        $this->assertCount(6, $detectors);
    }

    public function testScanVulnerableFile(): void
    {
        $vulnerableFile = __DIR__ . '/Fake/VulnerableCode.php';
        $vulnerabilities = $this->scanner->scanFile($vulnerableFile);

        $this->assertNotEmpty($vulnerabilities);
        $this->assertContainsOnlyInstancesOf(VulnerabilityInterface::class, $vulnerabilities);
    }

    public function testScanSafeFile(): void
    {
        $safeFile = __DIR__ . '/Fake/SafeCode.php';
        $vulnerabilities = $this->scanner->scanFile($safeFile);

        // Safe code should have minimal or no critical vulnerabilities
        $critical = array_filter(
            $vulnerabilities,
            static fn (VulnerabilityInterface $v) => $v->getSeverity() === VulnerabilityInterface::SEVERITY_CRITICAL
        );

        $this->assertEmpty($critical);
    }

    public function testScanDirectory(): void
    {
        $result = $this->scanner->scanDirectory(__DIR__ . '/Fake');

        $this->assertInstanceOf(ScanResult::class, $result);
        $this->assertGreaterThan(0, $result->getFilesScanned());
        $this->assertGreaterThan(0, $result->getScanTime());
    }

    public function testScanResultCounts(): void
    {
        $result = $this->scanner->scanDirectory(__DIR__ . '/Fake');

        $this->assertSame(
            $result->getVulnerabilityCount(),
            $result->getCriticalCount() + $result->getHighCount() + $result->getMediumCount() + $result->getLowCount()
        );
    }

    public function testSqlInjectionDetector(): void
    {
        $detector = new SqlInjectionDetector();
        $code = '<?php $pdo->query("SELECT * FROM users WHERE id = " . $_GET["id"]);';

        $vulnerabilities = $detector->scan('test.php', $code);

        $this->assertNotEmpty($vulnerabilities);
        $this->assertStringContainsString('SQL', $vulnerabilities[0]->getType());
    }

    public function testXssDetector(): void
    {
        $detector = new XssDetector();
        $code = '<?php echo $_GET["message"];';

        $vulnerabilities = $detector->scan('test.php', $code);

        $this->assertNotEmpty($vulnerabilities);
        $this->assertStringContainsString('XSS', $vulnerabilities[0]->getType());
    }

    public function testCommandInjectionDetector(): void
    {
        $detector = new CommandInjectionDetector();
        $code = '<?php exec("ls " . $_GET["path"]);';

        $vulnerabilities = $detector->scan('test.php', $code);

        $this->assertNotEmpty($vulnerabilities);
        $this->assertStringContainsString('COMMAND', $vulnerabilities[0]->getType());
    }

    public function testPathTraversalDetector(): void
    {
        $detector = new PathTraversalDetector();
        $code = '<?php include($_GET["page"]);';

        $vulnerabilities = $detector->scan('test.php', $code);

        $this->assertNotEmpty($vulnerabilities);
        $this->assertStringContainsString('PATH', $vulnerabilities[0]->getType());
    }

    public function testDangerousFunctionDetector(): void
    {
        $detector = new DangerousFunctionDetector();
        $code = '<?php eval($_POST["code"]);';

        $vulnerabilities = $detector->scan('test.php', $code);

        $this->assertNotEmpty($vulnerabilities);
    }

    public function testSessionSecurityDetector(): void
    {
        $detector = new SessionSecurityDetector();
        $code = '<?php session_id($_GET["sid"]);';

        $vulnerabilities = $detector->scan('test.php', $code);

        $this->assertNotEmpty($vulnerabilities);
        $this->assertStringContainsString('SESSION', $vulnerabilities[0]->getType());
    }

    public function testExcludePatterns(): void
    {
        $this->scanner->setExcludePatterns(['/Fake/']);
        $result = $this->scanner->scanDirectory(__DIR__);

        // Should not scan files in Fake directory
        $files = array_map(
            static fn (VulnerabilityInterface $v) => $v->getFile(),
            $result->getVulnerabilities()
        );

        foreach ($files as $file) {
            $this->assertStringNotContainsString('/Fake/', $file);
        }
    }

    public function testConsoleOutput(): void
    {
        $result = $this->scanner->scanDirectory(__DIR__ . '/Fake');
        $output = new ConsoleOutput(false);

        $formatted = $output->format($result);

        $this->assertStringContainsString('BEAR Security Scanner', $formatted);
        $this->assertStringContainsString('Summary', $formatted);
    }

    public function testJsonOutput(): void
    {
        $result = $this->scanner->scanDirectory(__DIR__ . '/Fake');
        $output = new JsonOutput();

        $json = $output->format($result);
        $data = json_decode($json, true);

        $this->assertIsArray($data);
        $this->assertArrayHasKey('summary', $data);
        $this->assertArrayHasKey('vulnerabilities', $data);
    }

    public function testVulnerabilityToArray(): void
    {
        $vulnerabilities = $this->scanner->scanFile(__DIR__ . '/Fake/VulnerableCode.php');

        if (count($vulnerabilities) > 0 && $vulnerabilities[0] instanceof \BEAR\SecurityScanner\Vulnerability) {
            $array = $vulnerabilities[0]->toArray();

            $this->assertArrayHasKey('type', $array);
            $this->assertArrayHasKey('severity', $array);
            $this->assertArrayHasKey('file', $array);
            $this->assertArrayHasKey('line', $array);
            $this->assertArrayHasKey('description', $array);
        } else {
            $this->markTestSkipped('No vulnerabilities found to test');
        }
    }

    public function testScanResultToArray(): void
    {
        $result = $this->scanner->scanDirectory(__DIR__ . '/Fake');
        $array = $result->toArray();

        $this->assertArrayHasKey('summary', $array);
        $this->assertArrayHasKey('vulnerabilities', $array);
        $this->assertIsArray($array['summary']);
        $this->assertArrayHasKey('files_scanned', $array['summary']);
        $this->assertArrayHasKey('total_vulnerabilities', $array['summary']);
    }

    public function testHasCriticalOrHigh(): void
    {
        $result = $this->scanner->scanDirectory(__DIR__ . '/Fake');

        if ($result->getCriticalCount() > 0 || $result->getHighCount() > 0) {
            $this->assertTrue($result->hasCriticalOrHigh());
        } else {
            $this->assertFalse($result->hasCriticalOrHigh());
        }
    }

    public function testCustomDetector(): void
    {
        $scanner = new Scanner([new SqlInjectionDetector()]);
        $detectors = $scanner->getDetectors();

        $this->assertCount(1, $detectors);
        $this->assertInstanceOf(SqlInjectionDetector::class, $detectors[0]);
    }

    public function testAddDetector(): void
    {
        $this->scanner->addDetector(new SqlInjectionDetector());
        $detectors = $this->scanner->getDetectors();

        // 6 default + 1 added
        $this->assertCount(7, $detectors);
    }

    public function testSetIncludeExtensions(): void
    {
        $this->scanner->setIncludeExtensions(['php']);
        $result = $this->scanner->scanDirectory(__DIR__ . '/Fake');

        $this->assertGreaterThan(0, $result->getFilesScanned());
    }
}
