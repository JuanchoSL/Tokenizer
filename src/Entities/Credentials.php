<?php

namespace JuanchoSL\Tokenizer\Entities;

use JuanchoSL\Tokenizer\Contracts\CredentialInterface;

class Credentials
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

    /**
     * Check if an username exists into the Credentials sequence
     * @param string $username The username to check
     * @return bool true if username exists into any credential
     */
    public function hasCredential(string $username): bool
    {
        return array_key_exists($username, $this->credentials);
    }

    /**
     * Retrieve the Credential from credentials where the username is equeal to sended
     * @param string $username Ther username to find
     * @return CredentialInterface|null The Credential entity if exists or null
     */
    public function getCredential(string $username): ?CredentialInterface
    {
        return $this->credentials[$username] ?? null;
    }

}
