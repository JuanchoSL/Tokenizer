<?php

declare(strict_types=1);

namespace JuanchoSL\Tokenizer\Entities;

use JuanchoSL\Exceptions\NotFoundException;
use JuanchoSL\Tokenizer\Contracts\CredentialInterface;
use JuanchoSL\Tokenizer\Contracts\CredentialsInterface;

class Credentials implements CredentialsInterface
{

    /**
     *
     * @var array<string,CredentialInterface>
     */
    private array $credentials = [];

    /**
     * Credentials collection
     * @param CredentialInterface $credentials sequence of credential entities
     */
    public function __construct(CredentialInterface ...$credentials)
    {
        foreach ($credentials as $credential) {
            $this->credentials[$credential->getUsername()] = $credential;
        }
    }

    public function hasCredential(string $username): bool
    {
        return array_key_exists($username, $this->credentials);
    }

    public function getCredential(string $username): CredentialInterface
    {
        if (!$this->hasCredential($username)) {
            throw new NotFoundException("The username {$username} is not into collection");
        }
        return $this->credentials[$username];
    }

}
