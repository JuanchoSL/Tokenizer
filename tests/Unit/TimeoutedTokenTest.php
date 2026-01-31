<?php

namespace JuanchoSL\Tokenizer\Tests\Unit;

use JuanchoSL\Exceptions\ForbiddenException;
use JuanchoSL\Tokenizer\Entities\Credential;
use JuanchoSL\Tokenizer\Entities\Credentials;
use JuanchoSL\Tokenizer\Repositories\BearerToken;
use JuanchoSL\Tokenizer\Repositories\JwtToken;
use PHPUnit\Framework\TestCase;

class TimeoutedTokenTest extends TestCase
{


    public function providerLoginData(): array
    {
        $credentials = new Credentials(new Credential('username', 'password'), new Credential('user', 'pass'));
        return [
            'bearer token' => [
                new BearerToken([
                    BearerToken::OPTION_CYPHER => 'Restricted area',
                    BearerToken::OPTION_TTL => 1
                ]),
                $credentials
            ],
            'jwt token' => [
                new JwtToken([
                    JwtToken::OPTION_TTL => 1,
                    JwtToken::OPTION_ISSUER => 'Restricted area',
                    JwtToken::OPTION_AUDIENCE => 'Restricted area'
                ]),
                $credentials
            ],
            /*
      'API key' => [
          new KeyToken,
          $credentials
      ],*/
        ];
    }

    /**
     * @dataProvider providerLoginData
     */
    public function testKoToken($tokenizer, $credentials): void
    {
        $token = $tokenizer->encode(new Credential('username', 'password'));
        $this->assertIsString($token);
        $this->assertStringContainsString($tokenizer::TYPE, $token);
        $token = trim(\str_replace($tokenizer::TYPE, '', $token));
        $credential = $tokenizer->decode($token);
        $this->assertInstanceOf(Credential::class, $credential);
        $this->assertTrue($credentials->hasCredential($credential->getUsername()));
        $credential = $credentials->getCredential($credential->getUsername());
        sleep(1);
        $this->expectException(ForbiddenException::class);
        $tokenizer->check($credential, $token);
    }
}
