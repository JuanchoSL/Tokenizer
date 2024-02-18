<?php

declare(strict_types=1);

namespace JuanchoSL\Tokenizer\Contracts;

interface CredentialInterface
{

    public function getUsername(): string;

    public function getPassword(): string;
}
