<?php

namespace JuanchoSL\Tokenizer\Tests\Unit;

use JuanchoSL\Tokenizer\Entities\Credential;
use JuanchoSL\Tokenizer\Entities\Credentials;
use JuanchoSL\Tokenizer\Repositories\BearerToken;
use PHPUnit\Framework\TestCase;

class BearerTokenTest extends TestCase
{

    private Credentials $credentials;

    public function setUp(): void
    {
        $this->credentials = new Credentials(new Credential('username', 'password'), new Credential('user', 'pass'));
    }

    public function testBearerToken(): void
    {
        $tokenizer = new BearerToken("Restricted area");
        $token = $tokenizer->encode(new Credential('username', 'password'));
        $this->assertIsString($token);
        $this->assertStringContainsString('Bearer', $token);
        $token = trim(\str_replace('Bearer', '', $token));
        $credential = $tokenizer->decode($token);
        $this->assertInstanceOf(Credential::class, $credential);
        $this->assertTrue($this->credentials->hasCredential($credential->getUsername()));
        $credential = $this->credentials->getCredential($credential->getUsername());
        $this->assertTrue($tokenizer->check($credential, $token));
    }

    public function testBearerTokenPassFail(): void
    {
        $tokenizer = new BearerToken("Restricted area");
        $token = $tokenizer->encode(new Credential('username', 'pass'));
        $this->assertIsString($token);
        $token = trim(\str_replace('Bearer', '', $token));
        $credential = $tokenizer->decode($token);
        $this->assertInstanceOf(Credential::class, $credential);
        $this->assertTrue($this->credentials->hasCredential($credential->getUsername()));
        $credential = $this->credentials->getCredential($credential->getUsername());
        $this->assertFalse($tokenizer->check($credential, $token));
    }

    public function testBearerTokenUserNotExists(): void
    {
        $tokenizer = new BearerToken("Restricted area");
        $token = $tokenizer->encode(new Credential('nameuser', 'pass'));
        $this->assertIsString($token);
        $token = trim(\str_replace('Bearer', '', $token));
        $credential = $tokenizer->decode($token);
        $this->assertInstanceOf(Credential::class, $credential);
        $this->assertFalse($this->credentials->hasCredential($credential->getUsername()));
    }

}
