<?php

namespace JuanchoSL\Tokenizer\Repositories;

use JuanchoSL\Tokenizer\Contracts\CredentialInterface;
use JuanchoSL\Tokenizer\Contracts\TokenInterface;
use JuanchoSL\Tokenizer\Entities\Credential;
use JuanchoSL\Exceptions\PreconditionFailedException;

class DigestToken implements TokenInterface
{

    const TYPE = 'Digest';
    const OPTION_REALM = 'realm';
    const OPTION_QOP = 'qop';
    const OPTION_URI = 'uri';
    private string $uri;
    private string $qop = 'auth';
    private string $realm;

    public function __construct(array $options)
    {
        foreach ([self::OPTION_REALM => 'realm', self::OPTION_URI => 'uri'] as $required_option => $requierd_field) {
            if (array_key_exists($required_option, $options)) {
                $this->{$requierd_field} = $options[$required_option];
            } else {
                throw new PreconditionFailedException("The option " . $required_option . " is mandatory");
            }
        }
        foreach ([self::OPTION_QOP => 'qop'] as $required_option => $requierd_field) {
            if (array_key_exists($required_option, $options)) {
                $this->{$requierd_field} = $options[$required_option];
            }
        }
        //$this->realm = $realm;
    }

    public function encode(CredentialInterface $credential): string
    {
        $uniqid = uniqid();
        $counter = "00000001";
        $response = $this->createResponse($credential, $uniqid, $counter, $this->uri);
        return self::TYPE . " username='" . $credential->getUsername() . "',realm='" . $this->realm . "',uri='" . $this->uri . "',qop='" . $this->qop . "',nc=" . $counter . ",cnonce='" . $uniqid . "',nonce='" . md5($this->realm) . "',response='" . $response . "'";
    }

    public function decode(string $token): ?CredentialInterface
    {
        $parts = $this->parse($token);
        if (empty($parts) || !is_array($parts) || !array_key_exists('username', $parts)) {
            throw new PreconditionFailedException("The provided token is invalid");
        }
        return new Credential($parts['username'], $token);
    }

    /**
     *
     * @param string $token
     * @return array<string,string>|null
     */
    private function parse(string $token): ?array
    {
        if (substr($token, 0, strlen(self::TYPE)) == self::TYPE) {
            $token = trim(str_replace(self::TYPE, '', $token));
        }
        // protect against missing data
        $needed_parts = array('nonce' => 1, 'nc' => 1, 'cnonce' => 1, 'qop' => 1, 'username' => 1, 'uri' => 1, 'response' => 1);
        $data = array();
        $keys = implode('|', array_keys($needed_parts));

        preg_match_all('@(' . $keys . ')=(?:([\'"])([^\2]+?)\2|([^\s,]+))@', $token, $matches, PREG_SET_ORDER);

        foreach ($matches as $m) {
            $data[$m[1]] = $m[3] ? $m[3] : $m[4];
            unset($needed_parts[$m[1]]);
        }
        return $needed_parts ? null : $data;
    }

    public function check(CredentialInterface $credential, string $token): bool
    {
        $parts = $this->parse($token);
        if (empty($parts)) {
            return false;
        }
        $response = $this->createResponse($credential, $parts['cnonce'], $parts['nc'], $parts['uri']);
        return $parts['response'] === $response;
    }

    private function createResponse(CredentialInterface $credential, string $uniqid, string $counter, string $uri): string
    {
        $A1 = md5($credential->getUsername() . ':' . $this->realm . ':' . $credential->getPassword());
        $A2 = md5('GET:' . $uri);
        return md5($A1 . ':' . md5($this->realm) . ':' . $counter . ':' . $uniqid . ':auth:' . $A2);
    }

}