# Encrypted Attribute Bundle

Symfony bundle providing a PHP 8 `Encrypted` attribute for Doctrine entities. Fields marked with this attribute are transparently encrypted before persistence and decrypted after load using AES-256-GCM.

## Install

```bash
composer require meritech/encrypted-attribute-bundle
```

Ensure an encryption key is set in your environment:

```bash
# 32-byte random key, base64-encoded
setx ENCRYPTION_KEY "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
```

Supports `base64:` and `hex:` prefixes. Raw binary string keys must be exactly 32 bytes.

## Configure

Register the bundle (if not using Flex auto-registration):

```php
// config/bundles.php
return [
    Meritech\EncryptionBundle\EncryptionBundle::class => ['all' => true],
];
```

Services are auto-registered from `config/services.php`. The Doctrine subscriber is tagged automatically.

### Configuration Options

Configure the bundle in your host Symfony app (examples shown in YAML and PHP):

```yaml
# config/packages/meritech_encryption.yaml
meritech_encryption:
  prefix: 'ENC.'                # ciphertext prefix
  aad: null                     # optional AAD string (must match on decrypt)
  excluded_entities: []         # FQCNs to skip
  current_kid: 'key-2025-12'    # key id tagged in new envelopes
  keys:                         # rotation map for decrypt by kid
    key-2025-11: 'base64:AAAA...'
    key-2025-12: 'base64:BBBB...'
```

```php
// config/packages/meritech_encryption.php
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $config) {
    $config->extension('meritech_encryption', [
        'prefix' => 'ENC.',
        'aad' => null,
        'excluded_entities' => [],
        'current_kid' => 'key-2025-12',
        'keys' => [
            'key-2025-11' => 'base64:AAAA...',
            'key-2025-12' => 'base64:BBBB...',
        ],
    ]);
};
```

Key material comes from the `ENCRYPTION_KEY` env (32-byte key). Prefix `base64:` or `hex:` to indicate encoding.

## Usage

Annotate entity properties:

```php
use Meritech\EncryptionBundle\Attribute\Encrypted;

class UserSecret
{
    #[Encrypted(type: 'string')]
    private ?string $token = null;

    #[Encrypted(type: 'json')]
    private array $profile = [];
}
```

The subscriber will:

- On `onFlush`: encrypt marked fields and recompute the change set
- On `postLoad`: decrypt envelopes back to plaintext/arrays in memory

Envelope format: `ENC.{json}`, where JSON contains `v`, `alg`, `iv`, `tag`, `ct`, optional `kid`, and `typ` (`plain` or `json`).

### Key Rotation Command

When you update `ENCRYPTION_KEY` and set a new `current_kid`, re-encrypt existing rows in your host app:

```powershell
php bin\console encryption:reencrypt --class App\Entity\UserSecret --batch-size 200
```

The command will:

- Decrypt current envelopes (using `keys` map by `kid`)
- Re-encrypt with the current key and tag envelopes with `current_kid`
- Flush in batches (default 100; configurable via `--batch-size`)

## Notes

- Nulls are preserved if `nullable=true`; empty strings are encrypted.
- Partial hydration/scalar queries bypass lifecycle events; ciphertext may be returned in those cases.
- Prefer TEXT columns; indexing encrypted fields is not meaningful. For lookups, store a separate hash column.

## Key Rotation

Provide `ENCRYPTION_KEY_ID` in env to tag new writes. A future console command can re-encrypt rows with a new key id.

## License

MIT
