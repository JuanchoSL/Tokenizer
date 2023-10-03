<?php

namespace JuanchoSL\Tokenizer\Tests\Functional;

use JuanchoSL\Exceptions\ForbiddenException;
use JuanchoSL\Exceptions\UnauthorizedException;
use JuanchoSL\Tokenizer\Contracts\TokenInterface;
use JuanchoSL\Tokenizer\Entities\Credential;
use JuanchoSL\Tokenizer\Entities\Credentials;
use JuanchoSL\Tokenizer\Repositories\JwtToken;
use JuanchoSL\Tokenizer\Services\Authentication;
use PHPUnit\Framework\TestCase;

class JwtAuthenticatorTest extends TestCase
{

    private Credentials $credentials;
    private TokenInterface $tokenizer;

    public function setUp(): void
    {
        $options = [
            JwtToken::OPTION_ISSUER => 'API_TOKEN',
            JwtToken::OPTION_AUDIENCE => 'API_TOKEN'
        ];
        $this->tokenizer = new JwtToken($options);
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