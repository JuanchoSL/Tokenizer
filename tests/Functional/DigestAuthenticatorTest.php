<?php

namespace JuanchoSL\Tokenizer\Tests\Functional;

use JuanchoSL\Exceptions\ForbiddenException;
use JuanchoSL\Exceptions\UnauthorizedException;
use JuanchoSL\Tokenizer\Contracts\TokenInterface;
use JuanchoSL\Tokenizer\Entities\Credential;
use JuanchoSL\Tokenizer\Entities\Credentials;
use JuanchoSL\Tokenizer\DigestToken;
use JuanchoSL\Tokenizer\Services\Authentication;
use PHPUnit\Framework\TestCase;

class DigestAuthenticatorTest extends TestCase
{

    private Credentials $credentials;
    private TokenInterface $tokenizer;

    public function setUp(): void
    {
        $this->tokenizer = new DigestToken(getenv('API_TOKEN'));
        $this->credentials = new Credentials(new Credential('username', 'password'), new Credential('user', 'pass'));
    }

    public function testOk(): void
    {
        $service = new Authentication($this->tokenizer, $this->credentials);
        $token = $service->generateToken(new Credential('username', 'password'));
        $this->assertIsString($token);
        $this->assertStringContainsString($this->tokenizer::TYPE, $token);
        $token = trim(\str_replace($this->tokenizer::TYPE, '', $token));
        $credential = $service->authenticateByToken($token);
        $this->assertInstanceOf(Credential::class, $credential);
    }

    public function testInvalidPass(): void
    {
        $service = new Authentication($this->tokenizer, $this->credentials);
        $token = $service->generateToken(new Credential('username', 'pass'));
        $this->assertIsString($token);
        $this->assertStringContainsString($this->tokenizer::TYPE, $token);
        $token = trim(\str_replace($this->tokenizer::TYPE, '', $token));
        $this->expectException(UnauthorizedException::class);
        $credential = $service->authenticateByToken($token);
    }

    public function testInvalidUser(): void
    {
        $service = new Authentication($this->tokenizer, $this->credentials);
        $token = $service->generateToken(new Credential('usermane', 'pass'));
        $this->assertIsString($token);
        $this->assertStringContainsString($this->tokenizer::TYPE, $token);
        $token = trim(\str_replace($this->tokenizer::TYPE, '', $token));
        $this->expectException(ForbiddenException::class);
        $credential = $service->authenticateByToken($token);
    }

}