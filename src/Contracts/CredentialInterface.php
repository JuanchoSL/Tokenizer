<?php

declare(strict_types=1);

namespace JuanchoSL\Tokenizer\Contracts;

interface CredentialInterface
{

    /**
     * Retrieve the username
     * @return string The username
     */
    public function getUsername(): string;


    /**
     * Retrieve the password
     * @return string The password
     */
    public function getPassword(): string;
}
