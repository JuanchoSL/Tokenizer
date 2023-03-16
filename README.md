# EnvVars

## Description
A small, lightweight utility to read ENV files and append his content to environment variables.

This is a test project in order to check how works the composer installation directly from GitHub

## Install
```
composer require juanchosl/envvars
```

## How use it
Load composer autoload and use the JuanchoSL\EnvVars\EnvVars class, with abstract _read_ method you can pass it the absolute file path or the dir path where the .ENV file are placed, the content has been putted into $\_ENV superglobal or you can use getenv(ENV_VAR_NAME) instead
```
use Juanchosl\EnvVars\EnvVars;
```
Then
```
EnvVars::read(realpath(dirname(__DIR__, 1)) . DIRECTORY_SEPARATOR . '.env');
```
Or
```
EnvVars::read(dirname(__DIR__, 1));
```
```
$env_var = getenv('ENV_VAR_NAME');
```
