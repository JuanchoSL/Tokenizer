<?php

namespace JuanchoSL\Tokenizer\Services;

use JuanchoSL\Tokenizer\Contracts\CredentialInterface;
use JuanchoSL\Tokenizer\Contracts\TokenInterface;
use JuanchoSL\Tokenizer\Entities\Credentials;
use JuanchoSL\Exceptions\ForbiddenException;
use JuanchoSL\Exceptions\UnauthorizedException;

class Authentication
{

    private Credentials $users;
    private TokenInterface $tokenizer;

    /**
     * Athentication service in order to authenticate a credential or token using the interfaces provided
     * @param TokenInterface $tokenizer Token authenticator to use
     * @param Credentials $credentials Sequence of credential for check into
     */
    public function __construct(TokenInterface $tokenizer, Credentials $credentials)
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
     * @throws ForbiddenException
     * @throws UnauthorizedException
     */
    public function authenticateByToken(string $token): CredentialInterface
    {
        $user = $this->tokenizer->decode($token);
        if (!$this->users->hasCredential($user->getUsername())) {
            throw new ForbiddenException("The user '{$user->getUsername()}' not exists");
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
     * @throws ForbiddenException
     * @throws UnauthorizedException
     */
    public function authenticateByCredential(CredentialInterface $credential): CredentialInterface
    {
        if (!$this->users->hasCredential($credential->getUsername())) {
            throw new ForbiddenException("The user '{$credential->getUsername()}' not exists");
        } else {
            $user = $this->users->getCredential($credential->getUsername());
            if ($user->getPassword() !== $credential->getPassword()) {
                throw new UnauthorizedException("The passsword for '{$credential->getUsername()}' is not correct");
            }
        }
        return $credential;
    }

}
