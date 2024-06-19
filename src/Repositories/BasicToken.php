<?php

declare(strict_types=1);

namespace JuanchoSL\Tokenizer\Repositories;

use JuanchoSL\Tokenizer\Contracts\CredentialInterface;
use JuanchoSL\Tokenizer\Contracts\TokenInterface;
use JuanchoSL\Tokenizer\Entities\Credential;
use JuanchoSL\Exceptions\PreconditionFailedException;

class BasicToken implements TokenInterface
{

    const TYPE = 'Basic';

    public function encode(CredentialInterface $credential): string
    {
        return self::TYPE . ' ' . base64_encode(implode(':', [$credential->getUsername(), $credential->getPassword()]));
    }

    public function check(CredentialInterface $credential, string $token): bool
    {
        $user = $this->decode($token);
        return $credential->getUsername() == $user->getUsername() && $credential->getPassword() == $user->getPassword();
    }

    public function decode(string $token): CredentialInterface
    {
        if (substr($token, 0, strlen(self::TYPE)) == self::TYPE) {
            $token = trim(str_replace(self::TYPE, '', $token));
        }
        $decoded = base64_decode($token, true);
        if (empty($decoded) || strpos($decoded, ':') === false) {
            throw new PreconditionFailedException('Invalid token');
        }

        list($username, $password) = explode(':', $decoded);
        if (empty($username) || empty($password)) {
            throw new PreconditionFailedException('Invalid token');
        }
        return new Credential($username, $password);
    }

}
