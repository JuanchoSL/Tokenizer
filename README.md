# Tokenizer

## Description
A small collection of encoder/decoder Token for authentication

This is a test project in order to check how works the composer installation directly from GitHub

## Install
```
composer require juanchosl/tokenizer
```

## How use it

### For create a token
```
$options = [
    JwtToken::OPTION_ISSUER => $_ENV['CYPHER_KEY'],
    JwtToken::OPTION_AUDIENCE => 'Restricted area'
];
$tokenizer = new JuanchoSL\Tokenizer\Repositories\JwtToken($options);
$token = $tokenizer->encode(new Credential($username, $password));
```

### For decode a token
```
$user_data = $tokenizer->decode($token);
```