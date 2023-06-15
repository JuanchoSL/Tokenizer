<?php

namespace JuanchoSL\Tokenizer\Tests\Unit;

use JuanchoSL\Tokenizer\Entities\Credential;
use JuanchoSL\Tokenizer\Entities\Credentials;
use JuanchoSL\Tokenizer\Repositories\DigestToken;
use PHPUnit\Framework\TestCase;

class DigestTokenTest extends TestCase
{

    private Credentials $credentials;

    public function setUp(): void
    {
        $this->credentials = new Credentials(new Credential('username', 'password'), new Credential('user', 'pass'));
    }

    public function testDigestToken(): void
    {
        $tokenizer = new DigestToken("Restricted area");
        $token = $tokenizer->encode(new Credential('username', 'password'));
        $this->assertIsString($token);
        $this->assertStringContainsString('Digest', $token);
        $token = trim(\str_replace('Digest', '', $token));
        $user = $tokenizer->decode($token);
        $this->assertTrue($this->credentials->hasCredential($user->getUsername()));
        $credential = $this->credentials->getCredential($user->getUsername());
        $this->assertTrue($tokenizer->check($credential, $token));
//        $response = $tokenizer->createResponse($credential, $parts['cnonce'], $parts['nc'], $parts['uri']);
//        $this->assertEquals($parts['response'], $response);
    }

    public function testDigestTokenPassFail(): void
    {
        $tokenizer = new DigestToken("Restricted area");
        $token = $tokenizer->encode(new Credential('username', 'pass'));
        $this->assertIsString($token);
        $this->assertStringContainsString('Digest', $token);
        $token = trim(\str_replace('Digest', '', $token));
        $user = $tokenizer->decode($token);
        $this->assertTrue($this->credentials->hasCredential($user->getUsername()));
        $credential = $this->credentials->getCredential($user->getUsername());
        $this->assertFalse($tokenizer->check($credential, $token));
//        $response = $tokenizer->createResponse($credential, $parts['cnonce'], $parts['nc'], $parts['uri']);
//        $this->assertNotEquals($parts['response'], $response);
    }

    public function testDigestTokenUserNotExists(): void
    {
        $tokenizer = new DigestToken("Restricted area");
        $token = $tokenizer->encode(new Credential('nameuser', 'pass'));
        $this->assertIsString($token);
        $this->assertStringContainsString('Digest', $token);
        $user = $tokenizer->decode(trim(\str_replace('Digest', '', $token)));
        $this->assertFalse($this->credentials->hasCredential($user->getUsername()));
    }

}
