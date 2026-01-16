<?php

declare(strict_types=1);

namespace Meritech\EncryptionBundle\Tests\Crypto;

use Meritech\EncryptionBundle\Crypto\KeyProvider;
use Meritech\EncryptionBundle\Exception\InvalidKeyException;
use Meritech\EncryptionBundle\Exception\KeyNotFoundException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(KeyProvider::class)]
final class KeyProviderTest extends TestCase
{
    private const VALID_KEY_RAW = '01234567890123456789012345678901'; // 32 bytes
    private const VALID_KEY_BASE64 = 'base64:MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=';
    private const VALID_KEY_HEX = 'hex:3031323334353637383930313233343536373839303132333435363738393031';

    public function testGetCurrentKeyWithRawKey(): void
    {
        $provider = new KeyProvider(self::VALID_KEY_RAW);

        $this->assertSame(self::VALID_KEY_RAW, $provider->getCurrentKey());
    }

    public function testGetCurrentKeyWithBase64Key(): void
    {
        $provider = new KeyProvider(self::VALID_KEY_BASE64);

        $this->assertSame(self::VALID_KEY_RAW, $provider->getCurrentKey());
    }

    public function testGetCurrentKeyWithHexKey(): void
    {
        $provider = new KeyProvider(self::VALID_KEY_HEX);

        $this->assertSame(self::VALID_KEY_RAW, $provider->getCurrentKey());
    }

    public function testGetCurrentKeyIdReturnsNullWhenNotSet(): void
    {
        $provider = new KeyProvider(self::VALID_KEY_RAW);

        $this->assertNull($provider->getCurrentKeyId());
    }

    public function testGetCurrentKeyIdReturnsConfiguredId(): void
    {
        $provider = new KeyProvider(self::VALID_KEY_RAW, 'key-v1');

        $this->assertSame('key-v1', $provider->getCurrentKeyId());
    }

    public function testGetKeyByIdReturnsPrimaryKeyForNullId(): void
    {
        $provider = new KeyProvider(self::VALID_KEY_RAW);

        $this->assertSame(self::VALID_KEY_RAW, $provider->getKeyById(null));
    }

    public function testGetKeyByIdReturnsPrimaryKeyForMatchingId(): void
    {
        $provider = new KeyProvider(self::VALID_KEY_RAW, 'key-v1');

        $this->assertSame(self::VALID_KEY_RAW, $provider->getKeyById('key-v1'));
    }

    public function testGetKeyByIdReturnsRotatedKey(): void
    {
        $rotatedKey = 'abcdefghijklmnopqrstuvwxyz012345'; // 32 bytes
        $provider = new KeyProvider(
            self::VALID_KEY_RAW,
            'key-v2',
            ['key-v1' => $rotatedKey]
        );

        $this->assertSame($rotatedKey, $provider->getKeyById('key-v1'));
    }

    public function testGetKeyByIdThrowsForUnknownKeyId(): void
    {
        $provider = new KeyProvider(self::VALID_KEY_RAW, 'key-v1');

        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessage("Key ID 'unknown-key' not found");

        $provider->getKeyById('unknown-key');
    }

    public function testGetBlindIndexKeyDerivedFromPrimaryWhenNotSet(): void
    {
        $provider = new KeyProvider(self::VALID_KEY_RAW);

        $blindIndexKey = $provider->getBlindIndexKey();

        // Should be SHA256 of primary key + ':blind-index'
        $expected = hash('sha256', self::VALID_KEY_RAW.':blind-index', binary: true);
        $this->assertSame($expected, $blindIndexKey);
    }

    public function testGetBlindIndexKeyReturnsConfiguredKey(): void
    {
        $blindKey = 'zyxwvutsrqponmlkjihgfedcba543210'; // 32 bytes
        $provider = new KeyProvider(
            self::VALID_KEY_RAW,
            null,
            [],
            $blindKey
        );

        $this->assertSame($blindKey, $provider->getBlindIndexKey());
    }

    public function testGetAllKeyIdsWithOnlyPrimaryKey(): void
    {
        $provider = new KeyProvider(self::VALID_KEY_RAW, 'key-v1');

        $this->assertSame(['key-v1'], $provider->getAllKeyIds());
    }

    public function testGetAllKeyIdsWithRotatedKeys(): void
    {
        $provider = new KeyProvider(
            self::VALID_KEY_RAW,
            'key-v3',
            [
                'key-v1' => 'abcdefghijklmnopqrstuvwxyz012345',
                'key-v2' => 'zyxwvutsrqponmlkjihgfedcba543210',
            ]
        );

        $ids = $provider->getAllKeyIds();

        $this->assertContains('key-v3', $ids);
        $this->assertContains('key-v1', $ids);
        $this->assertContains('key-v2', $ids);
        $this->assertSame('key-v3', $ids[0]); // Primary should be first
    }

    public function testGetAllKeyIdsWithNoPrimaryKeyId(): void
    {
        $provider = new KeyProvider(
            self::VALID_KEY_RAW,
            null,
            ['key-v1' => 'abcdefghijklmnopqrstuvwxyz012345']
        );

        $this->assertSame(['key-v1'], $provider->getAllKeyIds());
    }

    #[DataProvider('invalidKeyProvider')]
    public function testInvalidKeyThrowsException(string $key): void
    {
        $provider = new KeyProvider($key);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Key must be exactly 32 bytes for AES-256');

        $provider->getCurrentKey();
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidKeyProvider(): array
    {
        return [
            'too short' => ['short'],
            'too long' => [str_repeat('a', 64)],
            'empty' => [''],
            'invalid base64' => ['base64:invalid!!!'],
            'short base64' => ['base64:'.base64_encode('short')],
            'invalid hex' => ['hex:xyz'],
            'short hex' => ['hex:0102030405'],
        ];
    }
}
