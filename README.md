# Encryption Bundle

Symfony bundle for transparent Doctrine column encryption using custom DBAL types. Supports AES-256-GCM encryption with blind indexes for searchable encrypted data.

## Features

- **DBAL Types**: `encrypted_string`, `encrypted_text`, `encrypted_json`, `encrypted_string_deterministic`
- **Blind Indexes**: HMAC-based searchable encryption with configurable bit length
- **Key Rotation**: Multi-key support for seamless key rotation
- **Modern PHP**: Requires PHP 8.2+, uses readonly classes and modern syntax

## Requirements

- PHP 8.2+
- Symfony 6.4+ or 7.x
- Doctrine ORM 2.15+ or 3.x
- OpenSSL extension

## Installation

```bash
composer require meritech/encryption-bundle
```

Generate an encryption key (32 bytes, base64-encoded):

```bash
php -r "echo 'base64:' . base64_encode(random_bytes(32)) . PHP_EOL;"
```

Set the key in your environment:

```bash
# .env.local
ENCRYPTION_KEY="base64:your-generated-key-here"
```

## Configuration

```yaml
# config/packages/meritech_encryption.yaml
meritech_encryption:
    key:
        value: '%env(ENCRYPTION_KEY)%'
        id: 'k1'  # Optional key ID for rotation tracking

    # Previous keys for decrypting old data
    rotated_keys:
        k0: '%env(OLD_ENCRYPTION_KEY)%'

    # Separate key for blind indexes (recommended)
    blind_index_key: '%env(BLIND_INDEX_KEY)%'

    # Blind index defaults
    blind_index:
        default_bits: 64    # 16-256, lower = more privacy
        algorithm: sha256
```

Register the bundle (if not using Symfony Flex):

```php
// config/bundles.php
return [
    Meritech\EncryptionBundle\EncryptionBundle::class => ['all' => true],
];
```

## Usage

### Basic Encrypted Columns

Use DBAL types in your entity mappings:

```php
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
class User
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    // Encrypted string (randomized - different ciphertext each time)
    #[ORM\Column(type: 'encrypted_string')]
    private string $email;

    // Encrypted JSON data
    #[ORM\Column(type: 'encrypted_json', nullable: true)]
    private ?array $preferences = null;

    // Deterministic encryption (same plaintext = same ciphertext)
    // Use for exact-match searches without blind index
    #[ORM\Column(type: 'encrypted_string_deterministic')]
    private string $ssn;
}
```

### Searchable Encryption with Blind Index

For columns that need WHERE clause searches, use blind indexes:

```php
use Doctrine\ORM\Mapping as ORM;
use Meritech\EncryptionBundle\Attribute\BlindIndex;

#[ORM\Entity]
#[ORM\Index(columns: ['email_index'], name: 'idx_email_blind')]
class User
{
    #[ORM\Column(type: 'encrypted_string')]
    #[BlindIndex(indexProperty: 'emailIndex', bits: 64)]
    private string $email;

    // Blind index column - auto-populated on persist/update
    #[ORM\Column(type: 'blind_index', length: 16, nullable: true)]
    private ?string $emailIndex = null;

    public function getEmail(): string
    {
        return $this->email;
    }

    public function setEmail(string $email): self
    {
        $this->email = $email;
        return $this;
    }
}
```

### Querying with Blind Index

```php
use Meritech\EncryptionBundle\Crypto\BlindIndexer;

class UserRepository extends ServiceEntityRepository
{
    public function __construct(
        ManagerRegistry $registry,
        private readonly BlindIndexer $blindIndexer,
    ) {
        parent::__construct($registry, User::class);
    }

    public function findByEmail(string $email): ?User
    {
        // Compute blind index for the search value
        $normalized = $this->blindIndexer->normalize($email);
        $index = $this->blindIndexer->generate($normalized, 'User.email', 64);

        // Query - may return multiple results due to collisions
        $candidates = $this->createQueryBuilder('u')
            ->where('u.emailIndex = :index')
            ->setParameter('index', $index)
            ->getQuery()
            ->getResult();

        // Filter false positives by comparing decrypted values
        foreach ($candidates as $user) {
            if (mb_strtolower($user->getEmail()) === mb_strtolower($email)) {
                return $user;
            }
        }

        return null;
    }
}
```

## DBAL Types

| Type | Description |
|------|-------------|
| `encrypted_string` | Randomized AES-256-GCM encryption for strings |
| `encrypted_text` | Alias for `encrypted_string` (semantic) |
| `encrypted_json` | Encrypts arrays/objects as JSON |
| `encrypted_string_deterministic` | Same plaintext = same ciphertext (allows equality comparison) |
| `blind_index` | Simple VARCHAR for storing pre-computed blind indexes |

## Blind Index Configuration

The `#[BlindIndex]` attribute supports:

| Option | Default | Description |
|--------|---------|-------------|
| `indexProperty` | (required) | Property name for storing the blind index |
| `context` | `ClassName.propertyName` | HMAC domain separation context |
| `bits` | 64 | Output bits (16-256). Lower = more collisions = more privacy |
| `caseInsensitive` | true | Lowercase before hashing |

## Security Notes

- **Randomized encryption** (default): Same plaintext produces different ciphertext each time. Most secure but cannot be searched.
- **Deterministic encryption**: Same plaintext = same ciphertext. Leaks equality relationships. Use only when exact-match search is needed.
- **Blind indexes**: Truncated HMAC allows WHERE clause searches while preserving some privacy. Shorter bit length = more false positives = more privacy.
- **Key separation**: Use a separate `blind_index_key` so that compromising the blind index key doesn't reveal encrypted data.

## Key Rotation

1. Generate a new key and assign it a new ID
2. Add the current key to `rotated_keys`
3. Update `key.value` and `key.id` with the new key
4. Deploy - new data encrypted with new key, old data decrypted with rotated keys
5. Run migration to re-encrypt old data (implement in your application)

## License

MIT
