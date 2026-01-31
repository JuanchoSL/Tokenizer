<?php declare(strict_types=1);

namespace JuanchoSL\Tokenizer\Repositories;

use JuanchoSL\DataManipulation\Manipulators\Strings\StringsManipulators;
use JuanchoSL\Exceptions\ForbiddenException;
use JuanchoSL\Tokenizer\Contracts\CredentialInterface;
use JuanchoSL\Tokenizer\Contracts\TokenInterface;
use JuanchoSL\Tokenizer\Contracts\TokenParseableInterface;
use JuanchoSL\Tokenizer\Entities\Credential;
use JuanchoSL\Exceptions\PreconditionFailedException;

class JwtToken implements TokenInterface, TokenParseableInterface
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
        foreach ([static::OPTION_ISSUER => 'issuer', static::OPTION_AUDIENCE => 'audience', static::OPTION_TTL => 'ttl'] as $optional_option => $optional_field) {
            if (array_key_exists($optional_option, $options)) {
                $this->{$optional_field} = $options[$optional_option];
            }
        }
    }

    public function encode(CredentialInterface $credential): string
    {
        $header = [
            'alg' => $this->algorithm,
            'typ' => static::TYPE,
            'cty' => 'JWS'
        ];
        $payload = [
            'sub' => $credential->getUsername(),
            'iat' => time(),
            'exp' => time() + $this->ttl
        ];
        if (!empty($this->audience)) {
            $payload['aud'] = $this->audience;
        }
        if (!empty($this->issuer)) {
            $payload['iss'] = $this->issuer;
        }
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

        if (!array_key_exists('exp', $payload) || (int) $payload['exp'] <= time()) {
            throw new ForbiddenException("The token has been expired");
        }

        $base64UrlSignature = $this->generateSignature($header, $payload, $credential->getPassword());
        return ($base64UrlSignature === $signatureProvided &&
            (empty($this->issuer) || (array_key_exists('iss', $payload) && $payload['iss'] === $this->issuer)) &&
            (empty($this->audience) || (array_key_exists('aud', $payload) && $payload['aud'] === $this->audience)));
    }

    /**
     *
     * @param string $jwt
     * @return array<string, mixed>
     * @throws PreconditionFailedException
     */
    public function parse(string $jwt): array
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