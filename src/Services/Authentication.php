<?php

declare(strict_types=1);

namespace JuanchoSL\Tokenizer\Services;

use JuanchoSL\Tokenizer\Contracts\CredentialInterface;
use JuanchoSL\Tokenizer\Contracts\CredentialsInterface;
use JuanchoSL\Tokenizer\Contracts\TokenInterface;
use JuanchoSL\Exceptions\UnauthorizedException;

class Authentication
{

    private CredentialsInterface $users;
    private TokenInterface $tokenizer;

    /**
     * Athentication service in order to authenticate a credential or token using the interfaces provided
     * @param TokenInterface $tokenizer Token authenticator to use
     * @param CredentialsInterface $credentials Sequence of credential for check into
     */
    public function __construct(TokenInterface $tokenizer, CredentialsInterface $credentials)
    {
        $this->tokenizer = $tokenizer;
        $this->users = $credentials;
    }

    /**
     * Generate a token using the token instance used from the Credential provided
     * @param CredentialInterface $credential The credential to tokenize
     * @return string The token generated
     */
    public function generateToken(CredentialInterface $credential): string
    {
        return $this->tokenizer->encode($credential);
    }

    /**
     * Check using the token if credential exists into Credential sequence using the tokenizer
     * @param string $token The user token to check
     * @return CredentialInterface
     * @throws UnauthorizedException
     */
    public function authenticateByToken(string $token): CredentialInterface
    {
        $user = $this->tokenizer->decode($token);
        if (!$this->users->hasCredential($user->getUsername())) {
            throw new UnauthorizedException("The user '{$user->getUsername()}' not exists");
        }
        $credential = $this->users->getCredential($user->getUsername());
        if (!$this->tokenizer->check($credential, $token)) {
            throw new UnauthorizedException("The passsword for '{$credential->getUsername()}' is not correct");
        }
        return $credential;
    }

    /**
     * Check if provided credential exists into Credential sequence
     * @param CredentialInterface $credential The Credential to check
     * @return CredentialInterface
     * @throws UnauthorizedException
     */
    public function authenticateByCredential(CredentialInterface $credential): CredentialInterface
    {
        if (!$this->users->hasCredential($credential->getUsername())) {
            throw new UnauthorizedException("The user '{$credential->getUsername()}' not exists");
        } else {
            $user = $this->users->getCredential($credential->getUsername());
            if ($user->getPassword() !== $credential->getPassword()) {
                throw new UnauthorizedException("The passsword for '{$credential->getUsername()}' is not correct");
            }
        }
        return $credential;
    }

}
