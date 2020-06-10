<?php

use Jekhy\UcloudUfileStorage\UfileSdk;

function dd()
{
    var_dump(func_get_args());
    die();
}

class sdkTest extends PHPUnit\Framework\TestCase
{
    protected $sdk;

    protected function setUp(): void
    {
        $this->sdk = new UfileSdk('YourBucket', 'YourPublicKey', 'YourSecretKey');
    }

    public function testPutFile()
    {
        list($ret, $code) = $this->sdk->putFile('test.txt', __DIR__ . '/test.txt');
        $this->assertEquals($code, 200);
    }

    public function testPut()
    {
        list($ret, $code) = $this->sdk->put('dd', 'sdfsdfsdfsfsdf');
        $this->assertEquals($code, 200);
    }

    public function testGet()
    {
        $contents = $this->sdk->get('dd');

        $this->assertEquals($contents, 'sdfsdfsdfsfsdf');
    }

    public function testExists()
    {
        $exists = $this->sdk->exists('dd');
        $this->assertEquals($exists, true);
    }

    public function testSize()
    {
        $size = $this->sdk->size('dd');
        $this->assertEquals($size, 14);
    }

    public function testList()
    {
        list($ret, $code) = $this->sdk->list();
        $this->assertEquals($code, 200);
    }

}
