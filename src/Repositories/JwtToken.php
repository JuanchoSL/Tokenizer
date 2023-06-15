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

    private string $audience;

    public function __construct(string $audience)
    {
        $this->audience = $audience;
    }

    public function encode(CredentialInterface $credential): string
    {
        $header = [
            'alg' => 'HS256',
            'typ' => self::TYPE
        ];
        $payload = [
            'sub' => $credential->getUsername(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => $this->audience,
            'aud' => $this->audience
        ];
        $signature = $this->generateSignature($header, $payload, $credential->getPassword());
        $header = $this->base64UrlEncode(json_encode($header));
        $payload = $this->base64UrlEncode(json_encode($payload));
        return self::TYPE . ' ' . implode('.', [$header, $payload, $signature]);
    }

    public function decode(string $jwt): ?CredentialInterface
    {
        $parts = $this->parse($jwt);
        return (isset($parts['payload']['sub'])) ? new Credential($parts['payload']['sub'], $jwt) : null;
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
        return ($base64UrlSignature === $signatureProvided && $payload['iss'] === $this->audience);
    }

    /**
     *
     * @param string $jwt
     * @return array<string, array<string,string>|string>
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
     * @param array<string,string> $payload
     * @param string $cypher_key
     * @return string
     */
    private function generateSignature(array $headers, array $payload, string $cypher_key): string
    {
        $base64UrlHeader = $this->base64UrlEncode(json_encode($headers));
        $base64UrlPayload = $this->base64UrlEncode(json_encode($payload));
        $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, $cypher_key, true);
        return $this->base64UrlEncode($signature);
    }

}
