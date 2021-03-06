<?php

declare(strict_types=1);

namespace BEAR\Package;

use BEAR\AppMeta\Meta;
use BEAR\Package\Exception\InvalidContextException;
use FakeVendor\HelloWorld\Module\MetaModule;
use PHPUnit\Framework\TestCase;

class ModuleTest extends TestCase
{
    public function testModule(): void
    {
        $meta = new Meta('FakeVendor\HelloWorld', 'cli-app');
        $module = (new Module())($meta, 'cli-app');
        $this->assertStringContainsString('BEAR\AppMeta\AbstractAppMeta- => (object) BEAR\AppMeta\Meta', (string) $module);
    }

    public function testAppMetaInjection(): void
    {
        $meta = new Meta('FakeVendor\HelloWorld', 'meta-cli-app');
        $meta->appDir = '/tmp';
        (new Module())($meta, 'meta-cli-app');
        $this->assertSame('/tmp', MetaModule::$appDir);
    }

    public function testInvalidContet(): void
    {
        $this->expectException(InvalidContextException::class);
        $meta = new Meta('FakeVendor\HelloWorld', '__invalid__');
        $module = (new Module())($meta, '__invalid__');
    }
}
