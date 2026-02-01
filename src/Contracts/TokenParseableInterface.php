<?php

declare(strict_types=1);

namespace JuanchoSL\Tokenizer\Contracts;

use JuanchoSL\Tokenizer\Contracts\CredentialInterface;

interface TokenParseableInterface
{
    /**
     * Decode the token and create an array with decoded values
     * @param string $token
     * @return CredentialInterface
     */
    public function parse(string $token): array;
}