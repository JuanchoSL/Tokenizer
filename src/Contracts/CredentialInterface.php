<?php

namespace JuanchoSL\Tokenizer\Contracts;

interface CredentialInterface
{

    public function getUsername(): string;

    public function getPassword(): string;
}
