<?php

declare(strict_types=1);

namespace JuanchoSL\Tokenizer\Contracts;

use JuanchoSL\Tokenizer\Contracts\CredentialInterface;

interface CredentialsInterface
{


    /**
     * Check if an username exists into the Credentials sequence
     * @param string $username The username to check
     * @return bool true if username exists into any credential
     */
    public function hasCredential(string $username): bool;
    /**
     * Retrieve the Credential from credentials where the username is equeal to sended
     * @param string $username Ther username to find
     * @return CredentialInterface The Credential entity if exists
     */
    public function getCredential(string $username): CredentialInterface;
}