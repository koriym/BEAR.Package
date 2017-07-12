<?php
/**
 * This file is part of the BEAR.Package package.
 *
 * @license http://opensource.org/licenses/MIT MIT
 */
namespace MyVendor\MyApp\Resource\App\User;

use BEAR\Resource\ResourceObject;

class Friend extends ResourceObject
{
    public function onGet($id)
    {
        $this->body = [
            ['id' => '1', 'name' => 'Athos'],
            ['id' => '2', 'name' => 'Porthos'],
            ['id' => '3', 'name' => 'Aramis'],
        ];

        return $this;
    }
}
