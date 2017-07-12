<?php
/**
 * This file is part of the BEAR.Package package.
 *
 * @license http://opensource.org/licenses/MIT MIT
 */
namespace BEAR\Package;

use BEAR\AppMeta\AppMeta;
use BEAR\Package\Context\CliModule;
use BEAR\Sunday\Extension\Application\AppInterface;
use FakeVendor\HelloWorld\Module\App;
use FakeVendor\HelloWorld\Module\AppModule;
use FakeVendor\HelloWorld\Module\ProdModule;
use Ray\Di\Injector;

class NewAppTest extends \PHPUnit_Framework_TestCase
{
    public function testGetInstanceByHand()
    {
        $app = (new Injector(new AppMetaModule(new AppMeta('FakeVendor\HelloWorld'), new ProdModule(new CliModule(new AppModule()))), __DIR__ . '/tmp'))->getInstance(AppInterface::class);
        $this->assertInstanceOf(App::class, $app);

        return $app;
    }

    /**
     * @depends testGetInstanceByHand
     */
    public function testSerializable(App $app)
    {
        $this->assertInstanceOf(App::class, unserialize(serialize($app)));
    }
}
