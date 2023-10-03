<?php

namespace JuanchoSL\Tokenizer\Repositories;

use JuanchoSL\Tokenizer\Contracts\CredentialInterface;
use JuanchoSL\Tokenizer\Contracts\TokenInterface;
use JuanchoSL\Tokenizer\Entities\Credential;
use JuanchoSL\Exceptions\ForbiddenException;
use JuanchoSL\Exceptions\PreconditionFailedException;

class BearerToken implements TokenInterface
{

    const TYPE = 'Bearer';

    const OPTION_ALGORITHM = 'algorithm';
    const OPTION_CYPHER = 'cypher';
    const OPTION_TTL = 'ttl';
    private string $cypher;

    private string $algorithm = 'aes-256-cbc';
    private int $ttl = 3600;

    public function __construct(array $options)
    {
        foreach ([self::OPTION_CYPHER => 'cypher'] as $required_option => $requierd_field) {
            if (array_key_exists($required_option, $options)) {
                $this->{$requierd_field} = $options[$required_option];
            } else {
                throw new PreconditionFailedException("The option " . $required_option . " is mandatory");
            }
        }
        foreach ([self::OPTION_ALGORITHM => 'algorithm', self::OPTION_TTL => 'ttl'] as $required_option => $requierd_field) {
            if (array_key_exists($required_option, $options)) {
                $this->{$requierd_field} = $options[$required_option];
            }
        }
        //$this->cypher = $cypher;
    }

    public function encode(CredentialInterface $credential): string
    {
        $ivLength = openssl_cipher_iv_length($this->algorithm);
        $iv = openssl_random_pseudo_bytes($ivLength);

        return self::TYPE . ' ' . base64_encode($ivLength . strrev($iv) . openssl_encrypt(json_encode([
            'username' => $credential->getUsername(),
            'password' => $credential->getPassword(),
            'creationtime' => time(),
            'expire' => time() + $this->ttl
        ]), $this->algorithm, md5($this->cypher), OPENSSL_RAW_DATA, $iv));
    }

    public function decode(string $token): ?CredentialInterface
    {
        if (substr($token, 0, strlen(self::TYPE)) == self::TYPE) {
            $token = trim(str_replace(self::TYPE, '', $token));
        }
        $sEncrypted = base64_decode($token);
        $ivLength = openssl_cipher_iv_length($this->algorithm);
        $offset = strlen((string) $ivLength);
        $iv = strrev(substr($sEncrypted, $offset, $ivLength));
        $offset += strlen($iv);
        $decrypted = openssl_decrypt(substr($sEncrypted, $offset), $this->algorithm, md5($this->cypher), OPENSSL_RAW_DATA, $iv);

        if (empty($decrypted)) {
            throw new PreconditionFailedException("The provided token is invalid");
        }
        $json = json_decode($decrypted, true);
        if (json_last_error() != JSON_ERROR_NONE) {
            throw new PreconditionFailedException(json_last_error_msg());
        }
        extract($json);
        if (empty($username) || empty($password)) {
            throw new PreconditionFailedException("The provided token is invalid");
        }
        if (empty($expire) || $expire <= time()) {
            throw new ForbiddenException("The token has been expired");
        }
        return new Credential($username, $password);
    }

    public function check(CredentialInterface $credential, string $token): bool
    {
        $user = $this->decode($token);
        if (empty($user)) {
            return false;
        }
        return $credential->getUsername() == $user->getUsername() && $credential->getPassword() == $user->getPassword();
    }

}