<?php

namespace JuanchoSL\Tokenizer\Repositories;

use JuanchoSL\Tokenizer\Contracts\CredentialInterface;
use JuanchoSL\Tokenizer\Contracts\TokenInterface;
use JuanchoSL\Tokenizer\Entities\Credential;
use JuanchoSL\Exceptions\UnauthorizedException;
use JuanchoSL\Exceptions\PreconditionFailedException;

class JwtToken implements TokenInterface
{

    const TYPE = 'JWT';
    //const OPTION_ALGORITHM = 'alg';
    const OPTION_TTL = 'ttl';
    const OPTION_ISSUER = 'iss';
    const OPTION_AUDIENCE = 'aud';
    private string $audience;
    private int $ttl = 3600;
    private string $issuer;
    private string $algorithm = 'HS256';

    /**
     *
     * @param array<string,string|int> $options
     */
    public function __construct(array $options)
    {
        foreach ([self::OPTION_ISSUER => 'issuer', self::OPTION_AUDIENCE => 'audience'] as $required_option => $requierd_field) {
            if (array_key_exists($required_option, $options)) {
                $this->{$requierd_field} = $options[$required_option];
            } else {
                throw new PreconditionFailedException("The option " . $required_option . " is mandatory");
            }
        }
        foreach ([self::OPTION_TTL => 'ttl'] as $optional_option => $optional_field) {
            if (array_key_exists($optional_option, $options)) {
                $this->{$optional_field} = $options[$optional_option];
            }
        }
    }

    public function encode(CredentialInterface $credential): string
    {
        $header = [
            'alg' => $this->algorithm,
            'typ' => self::TYPE
        ];
        $payload = [
            'sub' => $credential->getUsername(),
            'iat' => time(),
            'exp' => time() + $this->ttl,
            'iss' => $this->issuer,
            'aud' => $this->audience
        ];
        $signature = $this->generateSignature($header, $payload, $credential->getPassword());
        $header = $this->base64UrlEncode(json_encode($header));
        $payload = $this->base64UrlEncode(json_encode($payload));
        return self::TYPE . ' ' . implode('.', [$header, $payload, $signature]);
    }

    public function decode(string $jwt): CredentialInterface
    {
        $parts = $this->parse($jwt);
        if (!isset($parts['payload']['sub'])) {
            throw new PreconditionFailedException("The provided token is invalid");
        }
        return new Credential($parts['payload']['sub'], $jwt);
    }

    public function check(CredentialInterface $credential, string $token): bool
    {
        $parts = $this->parse($token);
        $header = $parts['header'];
        $payload = $parts['payload'];
        $payload['sub'] = $credential->getUsername();
        $signatureProvided = $parts['signature'];

        if (!array_key_exists('exp', $payload) || (int) $payload['exp'] - time() < 0) {
            throw new UnauthorizedException("The token has been expired");
        }

        $base64UrlSignature = $this->generateSignature($header, $payload, $credential->getPassword());
        return ($base64UrlSignature === $signatureProvided && $payload['iss'] === $this->issuer);
    }

    /**
     *
     * @param string $jwt
     * @return array<string, mixed>
     * @throws PreconditionFailedException
     */
    private function parse(string $jwt): array
    {
        if (substr($jwt, 0, strlen(self::TYPE)) == self::TYPE) {
            $jwt = trim(str_replace(self::TYPE, '', $jwt));
        }
        $tokenParts = explode('.', $jwt);
        $header = json_decode($this->base64UrlDecode($tokenParts[0]), true);
        if (json_last_error() != JSON_ERROR_NONE) {
            throw new PreconditionFailedException(json_last_error_msg());
        }
        $payload = json_decode($this->base64UrlDecode($tokenParts[1]), true);
        if (json_last_error() != JSON_ERROR_NONE) {
            throw new PreconditionFailedException(json_last_error_msg());
        }
        return [
            'header' => $header,
            'payload' => $payload,
            'signature' => $tokenParts[2]
        ];
    }

    private function base64UrlEncode(string $data): string
    {
        $base64Url = strtr(base64_encode($data), '+/', '-_');

        return rtrim($base64Url, '=');
    }

    private function base64UrlDecode(string $base64Url): string
    {
        return base64_decode(strtr($base64Url, '-_', '+/'));
    }

    /**
     *
     * @param array<string,string> $headers
     * @param array<string,string|int> $payload
     * @param string $cypher_key
     * @return string
     * @throws PreconditionFailedException
     */
    private function generateSignature(array $headers, array $payload, string $cypher_key): string
    {
        $decoded_headers = json_encode($headers);
        if (!$decoded_headers) {
            throw new PreconditionFailedException(json_last_error_msg());
        }
        $base64UrlHeader = $this->base64UrlEncode($decoded_headers);
        $decoded_payload = json_encode($payload);
        if (!$decoded_payload) {
            throw new PreconditionFailedException(json_last_error_msg());
        }
        $base64UrlPayload = $this->base64UrlEncode($decoded_payload);
        $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, $cypher_key, true);
        return $this->base64UrlEncode($signature);
    }

}