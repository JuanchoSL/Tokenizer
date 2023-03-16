<?php

namespace JuanchoSL\Tokenizer\Tests\Unit;

use JuanchoSL\Tokenizer\Entities\Credential;
use JuanchoSL\Tokenizer\Entities\Credentials;
use JuanchoSL\Tokenizer\JwtToken;
use PHPUnit\Framework\TestCase;

class JwtTokenTest extends TestCase
{

    private Credentials $credentials;

    public function setUp(): void
    {
        $this->credentials = new Credentials(new Credential('username', 'password'), new Credential('user', 'pass'));
    }

    public function testJwtToken(): void
    {
        $tokenizer = new JwtToken('Restricted area');
        $token = $tokenizer->encode(new Credential('username', 'password'));
        $this->assertIsString($token);
        $this->assertStringContainsString('JWT', $token);
        $token = trim(\str_replace('JWT', '', $token));
        $credential = $tokenizer->decode($token);
        $this->assertInstanceOf(Credential::class, $credential);
        $this->assertTrue($this->credentials->hasCredential($credential->getUsername()));
        $credential = $this->credentials->getCredential($credential->getUsername());
        $this->assertTrue($tokenizer->check($credential, $token));
    }

    public function testJwtTokenPassFail(): void
    {
        $tokenizer = new JwtToken('Restricted area');
        $token = $tokenizer->encode(new Credential('username', 'pass'));
        $this->assertIsString($token);
        $this->assertStringContainsString('JWT', $token);
        $token = trim(\str_replace('JWT', '', $token));
        $credential = $tokenizer->decode($token);
        $this->assertInstanceOf(Credential::class, $credential);
        $this->assertTrue($this->credentials->hasCredential($credential->getUsername()));
        $credential = $this->credentials->getCredential($credential->getUsername());
        $this->assertFalse($tokenizer->check($credential, $token));
    }

    public function testJwtTokenUserNotExists(): void
    {
        $tokenizer = new JwtToken('Restricted area');
        $token = $tokenizer->encode(new Credential('nameuser', 'pass'));
        $this->assertIsString($token);
        $this->assertStringContainsString('JWT', $token);
        $token = trim(\str_replace('JWT', '', $token));
        $credential = $tokenizer->decode($token);
        $this->assertInstanceOf(Credential::class, $credential);
        $this->assertFalse($this->credentials->hasCredential($credential->getUsername()));
    }

}
