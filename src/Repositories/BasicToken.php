<?php declare(strict_types=1);

namespace JuanchoSL\Tokenizer\Repositories;

use JuanchoSL\DataManipulation\Manipulators\Strings\StringsManipulators;
use JuanchoSL\Tokenizer\Contracts\CredentialInterface;
use JuanchoSL\Tokenizer\Contracts\TokenInterface;
use JuanchoSL\Tokenizer\Contracts\TokenParseableInterface;
use JuanchoSL\Tokenizer\Entities\Credential;
use JuanchoSL\Exceptions\PreconditionFailedException;

class BasicToken implements TokenInterface, TokenParseableInterface
{

    const TYPE = 'Basic';

    const OPTION_HASHED = "hashing";

    private ?string $hashing = null;

    public function __construct(array $options = [])
    {
        foreach ([static::OPTION_HASHED] as $option) {
            $this->{$option} = array_key_exists($option, $options) ? $options[$option] : null;
        }
    }
    public function encode(CredentialInterface $credential): string
    {
        return (string) (new StringsManipulators($credential->getUsername()))
            ->concatenation($credential->getPassword(), ':')
            ->base64Encode()
            ->preppend(static::TYPE, ' ');
    }

    public function check(CredentialInterface $credential, string $token): bool
    {
        $user = $this->decode($token);
        $result = $credential->getUsername() == $user->getUsername();
        if ($result) {
            if (is_null($this->hashing)) {
                $result = $credential->getPassword() == $user->getPassword();
            } else {
                $result = password_verify($user->getPassword(), $credential->getPassword());
            }
        }
        return $result;
    }


    public function parse(string $token): array
    {
        if (substr($token, 0, strlen(static::TYPE)) == static::TYPE) {
            $token = trim(str_replace(static::TYPE, '', $token));
        }
        $decoded = base64_decode($token, true);
        if (empty($decoded) || strpos($decoded, ':') === false) {
            throw new PreconditionFailedException('Invalid token');
        }

        return explode(':', $decoded);
    }

    public function decode(string $token): CredentialInterface
    {
        list($username, $password) = $this->parse($token);
        if (empty($username) || empty($password)) {
            throw new PreconditionFailedException('Invalid token');
        }
        return new Credential($username, $password);
    }

}
