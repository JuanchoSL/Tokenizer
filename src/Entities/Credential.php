<?php

declare(strict_types=1);

namespace JuanchoSL\Tokenizer\Entities;

use JuanchoSL\Tokenizer\Contracts\CredentialInterface;

class Credential implements CredentialInterface, \JsonSerializable
{

    private string $username;
    private string $password;

    /**
     * Construct for Credential entity
     * @param string $username Credential username
     * @param string $password Credential password
     */
    public function __construct(string $username, string $password)
    {
        $this->username = $username;
        $this->password = $password;
    }

    /**
     * Retrieve the username value
     * @return string
     */
    public function getUsername(): string
    {
        return $this->username;
    }

    /**
     * Retrieve the password value
     * @return string
     */
    public function getPassword(): string
    {
        return $this->password;
    }

    public function jsonSerialize(): mixed
    {
        return [
            'username' => $this->getUsername(),
            'password' => $this->getPassword()
        ];
    }

}
