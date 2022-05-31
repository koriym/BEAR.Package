<?php

declare(strict_types=1);

namespace FakeVendor\HelloWorld\Module;

use BEAR\Resource\ResourceInterface;
use BEAR\Sunday\Extension\Application\AbstractApp;
use BEAR\Sunday\Extension\Application\AppInterface;
use BEAR\Sunday\Extension\Error\ErrorInterface;
use BEAR\Sunday\Extension\Error\ThrowableHandlerInterface;
use BEAR\Sunday\Extension\Router\RouterInterface;
use BEAR\Sunday\Extension\Transfer\HttpCacheInterface;
use BEAR\Sunday\Extension\Transfer\TransferInterface;
use Ray\Di\Di\Inject;

class App implements AppInterface
{
    public static $countOfNewInstance = 0;

    public $throwableHandler;

    /** @var HttpCacheInterface */
    public $httpCache;

    /** @var RouterInterface */
    public $router;

    /** @var TransferInterface */
    public $responder;

    /** @var ResourceInterface */
    public $resource;

    /** @var ErrorInterface */
    public $error;

    public function __construct(
        HttpCacheInterface $httpCache,
        RouterInterface $router,
        TransferInterface $responder,
        ResourceInterface $resource,
        ErrorInterface $error
    ) {
        $this->httpCache = $httpCache;
        $this->router = $router;
        $this->responder = $responder;
        $this->resource = $resource;
        $this->error = $error;
    }

    /**
     * @Inject
     */
    #[Inject]
    public function setThrowableHandler(ThrowableHandlerInterface  $handler)
    {
        $this->throwableHandler = $handler;
    }


}
