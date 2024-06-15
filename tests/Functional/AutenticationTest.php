<?php

namespace JuanchoSL\Tokenizer\Tests\Functional;

use JuanchoSL\Exceptions\UnauthorizedException;
use JuanchoSL\Tokenizer\Entities\Credential;
use JuanchoSL\Tokenizer\Entities\Credentials;
use JuanchoSL\Tokenizer\Repositories\BasicToken;
use JuanchoSL\Tokenizer\Repositories\BearerToken;
use JuanchoSL\Tokenizer\Repositories\DigestToken;
use JuanchoSL\Tokenizer\Repositories\JwtToken;
use JuanchoSL\Tokenizer\Services\Authentication;
use PHPUnit\Framework\TestCase;

class AutenticationTest extends TestCase
{

    public function providerLoginData(): array
    {
        $credentials = new Credentials(new Credential('username', 'password'), new Credential('user', 'pass'));
        return [
            'basic token' => [
                new BasicToken,
                $credentials
            ],
            'bearer token' => [
                new BearerToken([BearerToken::OPTION_CYPHER => 'API_TOKEN']),
                $credentials
            ],
            'digest token' => [
                new DigestToken([DigestToken::OPTION_REALM => 'API_TOKEN', DigestToken::OPTION_URI => 'API_TOKEN']),
                $credentials
            ],
            'jwt token' => [
                new JwtToken([
                    JwtToken::OPTION_ISSUER => 'API_TOKEN',
                    JwtToken::OPTION_AUDIENCE => 'API_TOKEN'
                ]),
                $credentials
            ],/*
          'API key' => [
              new KeyToken,
              $credentials
          ],*/
        ];
    }
    /**
     * @dataProvider providerLoginData
     */
    public function testOk($tokenizer, $credentials): void
    {
        echo $tokenizer::TYPE.PHP_EOL;
        $service = new Authentication($tokenizer, $credentials);
        $token = $service->generateToken(new Credential('username', 'password'));
        $this->assertIsString($token);
        $this->assertStringContainsString($tokenizer::TYPE, $token);
        $token = trim(\str_replace($tokenizer::TYPE, '', $token));
        $credential = $service->authenticateByToken($token);
        $this->assertInstanceOf(Credential::class, $credential);
    }

    /**
     * @dataProvider providerLoginData
     */
    public function testInvalidPass($tokenizer, $credentials): void
    {
        $service = new Authentication($tokenizer, $credentials);
        $token = $service->generateToken(new Credential('username', 'pass'));
        $this->assertIsString($token);
        $this->assertStringContainsString($tokenizer::TYPE, $token);
        $token = trim(\str_replace($tokenizer::TYPE, '', $token));
        $this->expectException(UnauthorizedException::class);
        $credential = $service->authenticateByToken($token);
    }

    /**
     * @dataProvider providerLoginData
     */
    public function testInvalidUser($tokenizer, $credentials): void
    {
        $service = new Authentication($tokenizer, $credentials);
        $token = $service->generateToken(new Credential('usermane', 'pass'));
        $this->assertIsString($token);
        $this->assertStringContainsString($tokenizer::TYPE, $token);
        $token = trim(\str_replace($tokenizer::TYPE, '', $token));
        $this->expectException(UnauthorizedException::class);
        $credential = $service->authenticateByToken($token);
    }

}