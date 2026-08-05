# Change Log - Tokenizer

## [1.0.5] - 2026-08-05

### Added

### Changed

- Phpunit version to v10

### Fixed

- Use static in tests dataproviders
- Removed constant type, avoiding error for php versions prior to 8.3

## [1.0.4] - 2026-02-01

### Added

- aud comparation for JWT check validation when has been setted into tokenizer
- Checked full compatibility with php 8.5
- BasicToken can use _password_verify_ function when local passwords are hashed using PASSWORD_BDCRYPT, PASSWORD_ARGON2I or PASSWORD_ARGON2ID, equals comparision if is not hashing constant provided

### Changed

- Change composer support from php v8.1
- Used StrinManipulators lib in order to unify criterias
- Now, Basic accept a password_verifying with hashed local password
- AuthenticateByCredential, now use the Credential converting it to token in order to verify using selected tokenizer, used for retrieve PHP*AUTH* server data and use for authenticate
- UnauthorizedException changed for ForbbidenException when token is timeouted
- Set to public the _parse_ method in order to decode the token and convert it to an array of values

### Fixed

- Digest data concatenation order
- For JWT, the ISS and AUD claims are now optional, according the RFC7519, if has been provide values to Tokenizer, it are compared with retrieved from decoded token

## [1.0.3] - 2023-06-20

### Added

- Constants for every Tokenizer in order to pass the array of parameters than can and needs to be setted
- PHPStan in DEV for quality code
- More documentation

### Changed

- Constructors now use an array of options

### Fixed

## [1.0.2] - 2023-06-15

### Added

- Github actions

### Changed

- Folder structure
- Namepaces

### Fixed

## [1.0.1] - 2023-03-24

### Added

- More unit tests
- Credential interface

### Changed

- Unify vars for Bearer token type

### Fixed

## [1.0.0] - 2023-03-16

### Added

- Initial release, first version

### Changed

### Fixed
