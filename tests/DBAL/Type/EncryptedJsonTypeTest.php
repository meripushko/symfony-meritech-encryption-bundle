<?php

declare(strict_types=1);

namespace Meritech\EncryptionBundle\Tests\DBAL\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Meritech\EncryptionBundle\Crypto\AesGcmEncryptor;
use Meritech\EncryptionBundle\Crypto\KeyProvider;
use Meritech\EncryptionBundle\DBAL\Type\AbstractEncryptedType;
use Meritech\EncryptionBundle\DBAL\Type\EncryptedJsonType;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

#[CoversClass(EncryptedJsonType::class)]
final class EncryptedJsonTypeTest extends TestCase
{
    private const TEST_KEY = '01234567890123456789012345678901';

    private EncryptedJsonType $type;
    private AbstractPlatform&MockObject $platform;
    private AesGcmEncryptor $encryptor;

    protected function setUp(): void
    {
        $this->type = new EncryptedJsonType();
        $this->platform = $this->createMock(AbstractPlatform::class);

        $keyProvider = new KeyProvider(self::TEST_KEY);
        $this->encryptor = new AesGcmEncryptor($keyProvider);
        AbstractEncryptedType::setEncryptor($this->encryptor);
    }

    protected function tearDown(): void
    {
        $reflection = new \ReflectionClass(AbstractEncryptedType::class);
        $property = $reflection->getProperty('encryptor');
        $property->setValue(null, null);
    }

    public function testGetNameReturnsCorrectName(): void
    {
        $this->assertSame('encrypted_json', $this->type->getName());
    }

    public function testConvertToDatabaseValueEncryptsArray(): void
    {
        $data = ['key' => 'value', 'number' => 42];

        $result = $this->type->convertToDatabaseValue($data, $this->platform);

        $this->assertNotNull($result);
        $this->assertStringStartsWith('ENC$1$', $result);
    }

    public function testConvertToDatabaseValueReturnsNullForNull(): void
    {
        $result = $this->type->convertToDatabaseValue(null, $this->platform);

        $this->assertNull($result);
    }

    public function testConvertToPHPValueDecryptsToArray(): void
    {
        $data = ['key' => 'value', 'number' => 42];
        $json = json_encode($data);
        $this->assertIsString($json);
        $encrypted = $this->encryptor->encrypt($json);

        $result = $this->type->convertToPHPValue($encrypted, $this->platform);

        $this->assertSame($data, $result);
    }

    public function testConvertToPHPValueReturnsNullForNull(): void
    {
        $result = $this->type->convertToPHPValue(null, $this->platform);

        $this->assertNull($result);
    }

    public function testConvertToPHPValueReturnsNullForEmptyString(): void
    {
        $result = $this->type->convertToPHPValue('', $this->platform);

        $this->assertNull($result);
    }

    public function testRoundTripEncryptionDecryption(): void
    {
        $original = [
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'metadata' => [
                'created' => '2024-01-01',
                'active' => true,
            ],
        ];

        $encrypted = $this->type->convertToDatabaseValue($original, $this->platform);
        $decrypted = $this->type->convertToPHPValue($encrypted, $this->platform);

        $this->assertSame($original, $decrypted);
    }

    public function testHandlesUnicodeCharactersInJson(): void
    {
        $original = [
            'greeting' => 'こんにちは',
            'emoji' => '🌍',
            'accent' => 'émoji',
        ];

        $encrypted = $this->type->convertToDatabaseValue($original, $this->platform);
        $decrypted = $this->type->convertToPHPValue($encrypted, $this->platform);

        $this->assertSame($original, $decrypted);
    }

    public function testPreservesZeroFraction(): void
    {
        $original = ['amount' => 10.0];

        $encrypted = $this->type->convertToDatabaseValue($original, $this->platform);
        $decrypted = $this->type->convertToPHPValue($encrypted, $this->platform);

        $this->assertSame(10.0, $decrypted['amount']);
    }

    public function testHandlesNestedArrays(): void
    {
        $original = [
            'level1' => [
                'level2' => [
                    'level3' => ['deep' => 'value'],
                ],
            ],
        ];

        $encrypted = $this->type->convertToDatabaseValue($original, $this->platform);
        $decrypted = $this->type->convertToPHPValue($encrypted, $this->platform);

        $this->assertSame($original, $decrypted);
    }

    public function testHandlesEmptyArray(): void
    {
        $original = [];

        $encrypted = $this->type->convertToDatabaseValue($original, $this->platform);
        $decrypted = $this->type->convertToPHPValue($encrypted, $this->platform);

        $this->assertSame($original, $decrypted);
    }

    public function testGetSQLDeclarationReturnsClobType(): void
    {
        $this->platform
            ->expects($this->once())
            ->method('getClobTypeDeclarationSQL')
            ->with([])
            ->willReturn('TEXT');

        $result = $this->type->getSQLDeclaration([], $this->platform);

        $this->assertSame('TEXT', $result);
    }

    public function testHandlesUnencryptedJsonValueForMigration(): void
    {
        // Unencrypted JSON should be decoded directly (migration scenario)
        $jsonValue = '{"key":"value"}';
        $result = $this->type->convertToPHPValue($jsonValue, $this->platform);

        $this->assertSame(['key' => 'value'], $result);
    }
}
