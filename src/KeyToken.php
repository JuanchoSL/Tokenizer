<?php

namespace App\Context\Infrastructure\Adapters\Token;

use App\Context\Domain\Contracts\TokenInterface;
use App\Context\Domain\Contracts\CredentialInterface;
use App\Context\Domain\Entities\Credential;

class KeyToken implements TokenInterface
{

    public function check(CredentialInterface $credential, string $token): bool
    {
        return $token == getenv('API_TOKEN');
    }

    public function decode(string $token): ?CredentialInterface
    {
        return new Credential($token, '');
    }

    public function encode(CredentialInterface $credential): string
    {
        return getenv('API_TOKEN');
    }

}
