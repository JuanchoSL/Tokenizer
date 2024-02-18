<?php

declare(strict_types=1);

namespace JuanchoSL\Tokenizer\Contracts;

use JuanchoSL\Tokenizer\Contracts\CredentialInterface;

interface CredentialsInterface
{

    public function hasCredential(string $username): bool;

    public function getCredential(string $username): CredentialInterface;
}