# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.3] - 2025-01-17

### Added

- GitHub Actions CI workflow with test matrix for PHP 8.2, 8.3, and 8.4
- PHPStan static analysis at level 8
- PHP CS Fixer code style checks in CI
- Comprehensive PHPUnit test suite for crypto components and DBAL types
- PHPUnit configuration (`phpunit.xml.dist`)
- PHPStan configuration (`phpstan.neon.dist`)
- `.gitattributes` for line ending normalization and export-ignore rules
- Makefile with helpful development commands (`make test`, `make phpstan`, `make ci`)

### Changed

- Updated `composer.json` with expanded keywords and support URLs
- CI uses `composer update` instead of `composer install` for cross-PHP version compatibility
- Removed `composer.lock` from version control (libraries should not commit lock files)

### Fixed

- PHPStan level 8 compliance - added proper type annotations throughout codebase
- CI compatibility with PHP 8.2 by not locking to PHP 8.4-only dependencies

## [1.0.0] - 2025-01-16

### Added

- Initial release of the Meritech Encryption Bundle
- AES-256-GCM encryption with randomized IV for maximum security
- Deterministic encryption for searchable encrypted columns
- Blind index support for privacy-preserving searches using HMAC
- Custom Doctrine DBAL types:
  - `encrypted_string` - Randomized string encryption
  - `encrypted_text` - Alias for encrypted_string (TEXT column type)
  - `encrypted_json` - Encrypted JSON data with automatic serialization
  - `encrypted_string_deterministic` - Deterministic encryption for equality searches
  - `blind_index` - Simple string type for blind index columns
- Key rotation support with seamless decryption of old data
- Configurable blind index bit length (16-256 bits)
- Support for multiple hash algorithms (SHA-256, SHA-384, SHA-512)
- Case-insensitive normalization for blind indexes
- Automatic Doctrine DBAL type registration via bundle configuration
- Comprehensive configuration options via `meritech_encryption.yaml`
- Support for Symfony 6.4+ and 7.0+
- Support for Doctrine ORM 2.15+ and 3.0+
- Support for Doctrine DBAL 3.6+ and 4.0+
- PHP 8.2+ required with OpenSSL extension
