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
$tokenizer = new JuanchoSL\Tokenizer\Repositories\JwtToken($_ENV['CYPHER_KEY']);
$token = $tokenizer->encode(new Credential($username, $password));
```

### For decode a token
```
$user_data = $tokenizer->decode($token);
```