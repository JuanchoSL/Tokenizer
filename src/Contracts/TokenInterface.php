<?php

namespace JuanchoSL\Tokenizer\Contracts;

use JuanchoSL\Tokenizer\Contracts\CredentialInterface;

interface TokenInterface
{
    const TYPE = '';
    public function encode(CredentialInterface $credential): string;
    public function decode(string $token): ? CredentialInterface;
    public function check(CredentialInterface $credential, string $token): bool;
}