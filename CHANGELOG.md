# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
