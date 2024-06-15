# Tokenizer

## Description

A small collection of encoder/decoder Token for authentication

This is a test project in order to check how works the composer installation directly from GitHub

## Install

```bash
composer require juanchosl/tokenizer
```

## How use it

### Entities
The system use a __CredentialInterface__ as DTO, a simple object with username and password

All credentials needs to be pushed into a __CredentialsInterface__ collection, a sequence of available usersto compare.
We provide a simple Collection in order to push a few users, but is importante that you create your own implementation in order to search usrs into database, as usual

In a login request, you needs to ensure the username+password validation brefore create a token

### Use a concret Tokenizer

#### For create a token

```php
$options = [
    JwtToken::OPTION_ISSUER => $_ENV['CYPHER_KEY'],
    JwtToken::OPTION_AUDIENCE => 'Restricted area'
];
$tokenizer = new JuanchoSL\Tokenizer\Repositories\JwtToken($options);
$token = $tokenizer->encode(new Credential($username, $password));
```

#### For decode a token

```php
$user_data = $tokenizer->decode($token);
```

#### For a check a token with a previously retrieved user

```php
$tokenizer->check($db_data, $token):
```

### Use the provided service

#### For create a token
```php
$options = [
    JwtToken::OPTION_ISSUER => $_ENV['CYPHER_KEY'],
    JwtToken::OPTION_AUDIENCE => 'Restricted area'
];
$tokenizer = new JuanchoSL\Tokenizer\Repositories\JwtToken($options);
$service = new Authentication($tokenizer, new Credentials);
$service->authenticateByCredential($credential);
return $service->generateToken($credential);
```

#### For decode a token
```php
$options = [
    JwtToken::OPTION_ISSUER => $_ENV['CYPHER_KEY'],
    JwtToken::OPTION_AUDIENCE => 'Restricted area'
];
$tokenizer = new JuanchoSL\Tokenizer\Repositories\JwtToken($options);
$service = new Authentication($tokenizer, new Credentials);
return $service->->authenticateByToken($token);
```
