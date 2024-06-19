<?php

namespace JuanchoSL\Tokenizer\Tests\Unit;

use JuanchoSL\Tokenizer\Entities\Credential;
use JuanchoSL\Tokenizer\Entities\Credentials;
use JuanchoSL\Tokenizer\Repositories\BasicToken;
use JuanchoSL\Tokenizer\Repositories\BearerToken;
use JuanchoSL\Tokenizer\Repositories\DigestToken;
use JuanchoSL\Tokenizer\Repositories\JwtToken;
use PHPUnit\Framework\TestCase;

class TokenTest extends TestCase
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
                new BearerToken([BearerToken::OPTION_CYPHER => 'Restricted area']),
                $credentials
            ],
            'digest token' => [
                new DigestToken([DigestToken::OPTION_REALM => 'API_TOKEN', DigestToken::OPTION_URI => 'API_TOKEN']),
                $credentials
            ],
            'jwt token' => [
                new JwtToken([
                    JwtToken::OPTION_ISSUER => 'Restricted area',
                    JwtToken::OPTION_AUDIENCE => 'Restricted area'
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
    public function testOkToken($tokenizer, $credentials): void
    {
        $token = $tokenizer->encode(new Credential('username', 'password'));
        $this->assertIsString($token);
        $this->assertStringContainsString($tokenizer::TYPE, $token);
        $token = trim(\str_replace($tokenizer::TYPE, '', $token));
        $credential = $tokenizer->decode($token);
        $this->assertInstanceOf(Credential::class, $credential);
        $this->assertTrue($credentials->hasCredential($credential->getUsername()));
        $credential = $credentials->getCredential($credential->getUsername());
        $this->assertTrue($tokenizer->check($credential, $token));
    }

    /**
     * @dataProvider providerLoginData
     */
    public function testTokenPassFail($tokenizer, $credentials): void
    {
        $token = $tokenizer->encode(new Credential('username', 'pass'));
        $this->assertIsString($token);
        $this->assertStringContainsString($tokenizer::TYPE, $token);
        $token = trim(\str_replace($tokenizer::TYPE, '', $token));
        $credential = $tokenizer->decode($token);
        $this->assertInstanceOf(Credential::class, $credential);
        $this->assertTrue($credentials->hasCredential($credential->getUsername()));
        $credential = $credentials->getCredential($credential->getUsername());
        $this->assertFalse($tokenizer->check($credential, $token));
    }

    /**
     * @dataProvider providerLoginData
     */
    public function testTokenUserNotExists($tokenizer, $credentials): void
    {
        $token = $tokenizer->encode(new Credential('nameuser', 'pass'));
        $this->assertIsString($token);
        $this->assertStringContainsString($tokenizer::TYPE, $token);
        $token = trim(\str_replace($tokenizer::TYPE, '', $token));
        $credential = $tokenizer->decode($token);
        $this->assertInstanceOf(Credential::class, $credential);
        $this->assertFalse($credentials->hasCredential($credential->getUsername()));
    }

}
