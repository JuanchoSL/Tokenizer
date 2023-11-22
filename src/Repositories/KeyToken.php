<?php

namespace JuanchoSL\Tokenizer\Repositories;

use JuanchoSL\Tokenizer\Contracts\TokenInterface;
use JuanchoSL\Tokenizer\Contracts\CredentialInterface;
use JuanchoSL\Tokenizer\Entities\Credential;

class KeyToken implements TokenInterface
{

    public function check(CredentialInterface $credential, string $token): bool
    {
        return $token == $credential->getUsername();
    }

    public function decode(string $token): CredentialInterface
    {
        return new Credential($token, $token);
    }

    public function encode(CredentialInterface $credential): string
    {
        return $credential->getUsername();
    }

}