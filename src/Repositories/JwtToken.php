<?php declare(strict_types=1);

namespace JuanchoSL\Tokenizer\Repositories;

use JuanchoSL\DataManipulation\Manipulators\Strings\StringsManipulators;
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
        foreach ([static::OPTION_ISSUER => 'issuer', static::OPTION_AUDIENCE => 'audience'] as $required_option => $requierd_field) {
            if (array_key_exists($required_option, $options)) {
                $this->{$requierd_field} = $options[$required_option];
            } else {
                throw new PreconditionFailedException("The option " . $required_option . " is mandatory");
            }
        }
        foreach ([static::OPTION_TTL => 'ttl'] as $optional_option => $optional_field) {
            if (array_key_exists($optional_option, $options)) {
                $this->{$optional_field} = $options[$optional_option];
            }
        }
    }

    public function encode(CredentialInterface $credential): string
    {
        $header = [
            'alg' => $this->algorithm,
            'typ' => static::TYPE
        ];
        $payload = [
            'sub' => $credential->getUsername(),
            'iat' => time(),
            'exp' => time() + $this->ttl,
            'iss' => $this->issuer,
            'aud' => $this->audience
        ];
        $signature = $this->generateSignature($header, $payload, $credential->getPassword());
        $header = (new StringsManipulators(json_encode($header)))->base64Encode()->trim('=')->__tostring();
        $payload = (new StringsManipulators(json_encode($payload)))->base64Encode()->trim('=')->__tostring();
        return static::TYPE . ' ' . implode('.', [$header, $payload, $signature]);
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
        return ($base64UrlSignature === $signatureProvided && $payload['iss'] === $this->issuer && $payload['aud'] === $this->audience);
    }

    /**
     *
     * @param string $jwt
     * @return array<string, mixed>
     * @throws PreconditionFailedException
     */
    private function parse(string $jwt): array
    {
        if (substr($jwt, 0, strlen(static::TYPE)) == static::TYPE) {
            $jwt = trim(str_replace(static::TYPE, '', $jwt));
        }
        $tokenParts = (new StringsManipulators($jwt))->explode('.');
        $header = json_decode($tokenParts[0]->base64UrlDecode()->__tostring(), true);
        if (json_last_error() != JSON_ERROR_NONE) {
            throw new PreconditionFailedException(json_last_error_msg());
        }
        $payload = json_decode($tokenParts[1]->base64UrlDecode()->__tostring(), true);
        if (json_last_error() != JSON_ERROR_NONE) {
            throw new PreconditionFailedException(json_last_error_msg());
        }
        return [
            'header' => $header,
            'payload' => $payload,
            'signature' => $tokenParts[2]->__tostring()
        ];
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
        $decoded_payload = json_encode($payload);
        if (!$decoded_payload) {
            throw new PreconditionFailedException(json_last_error_msg());
        }
        $base64UrlPayload = (new StringsManipulators($decoded_payload))->base64UrlEncode();

        $decoded_headers = json_encode($headers);
        if (!$decoded_headers) {
            throw new PreconditionFailedException(json_last_error_msg());
        }
        return (new StringsManipulators($decoded_headers))
            ->base64UrlEncode()
            ->concatenation($base64UrlPayload->__tostring(), '.')
            ->hashHmac('sha256', $cypher_key, true)
            ->base64UrlEncode()
            ->__tostring();
    }

}