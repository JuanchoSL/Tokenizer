<?php

namespace JuanchoSL\Tokenizer\Contracts;

use JuanchoSL\Tokenizer\Contracts\CredentialInterface;

interface TokenInterface
{
    const TYPE = '';
    /**
     * Create a token with the values passed
     * @param CredentialInterface $credential
     * @return string
     */
    public function encode(CredentialInterface $credential): string;
    /**
     * Decode the token and create a Credential object if is a know user
     * @param string $token
     * @return CredentialInterface
     */
    public function decode(string $token): CredentialInterface;
    /**
     * Check the Credential passed with the token in order to verify it
     * @param CredentialInterface $credential
     * @param string $token
     * @return bool
     */
    public function check(CredentialInterface $credential, string $token): bool;
}