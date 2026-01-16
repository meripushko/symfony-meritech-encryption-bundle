<?php

declare(strict_types=1);

namespace Meritech\EncryptionBundle\Tests\DBAL\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Meritech\EncryptionBundle\Crypto\AesGcmEncryptor;
use Meritech\EncryptionBundle\Crypto\KeyProvider;
use Meritech\EncryptionBundle\DBAL\Type\AbstractEncryptedType;
use Meritech\EncryptionBundle\DBAL\Type\EncryptedStringType;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

#[CoversClass(EncryptedStringType::class)]
#[CoversClass(AbstractEncryptedType::class)]
final class EncryptedStringTypeTest extends TestCase
{
    private const TEST_KEY = '01234567890123456789012345678901';

    private EncryptedStringType $type;
    private AbstractPlatform&MockObject $platform;
    private AesGcmEncryptor $encryptor;

    protected function setUp(): void
    {
        $this->type = new EncryptedStringType();
        $this->platform = $this->createMock(AbstractPlatform::class);

        $keyProvider = new KeyProvider(self::TEST_KEY);
        $this->encryptor = new AesGcmEncryptor($keyProvider);
        AbstractEncryptedType::setEncryptor($this->encryptor);
    }

    protected function tearDown(): void
    {
        // Reset static encryptor to avoid polluting other tests
        $reflection = new \ReflectionClass(AbstractEncryptedType::class);
        $property = $reflection->getProperty('encryptor');
        $property->setValue(null, null);
    }

    public function testGetNameReturnsCorrectName(): void
    {
        $this->assertSame('encrypted_string', $this->type->getName());
    }

    public function testConvertToDatabaseValueEncryptsString(): void
    {
        $result = $this->type->convertToDatabaseValue('hello world', $this->platform);

        $this->assertNotNull($result);
        $this->assertStringStartsWith('ENC$1$', $result);
    }

    public function testConvertToDatabaseValueReturnsNullForNull(): void
    {
        $result = $this->type->convertToDatabaseValue(null, $this->platform);

        $this->assertNull($result);
    }

    public function testConvertToDatabaseValueIsIdempotent(): void
    {
        $encrypted = $this->encryptor->encrypt('hello world');
        $result = $this->type->convertToDatabaseValue($encrypted, $this->platform);

        // Already encrypted value should not be double-encrypted
        $this->assertSame($encrypted, $result);
    }

    public function testConvertToPHPValueDecryptsString(): void
    {
        $encrypted = $this->encryptor->encrypt('hello world');
        $result = $this->type->convertToPHPValue($encrypted, $this->platform);

        $this->assertSame('hello world', $result);
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

    public function testConvertToPHPValueHandlesUnencryptedValueForMigration(): void
    {
        // Unencrypted values should pass through (migration scenario)
        $result = $this->type->convertToPHPValue('plain text value', $this->platform);

        $this->assertSame('plain text value', $result);
    }

    public function testRoundTripEncryptionDecryption(): void
    {
        $original = 'sensitive data';

        $encrypted = $this->type->convertToDatabaseValue($original, $this->platform);
        $decrypted = $this->type->convertToPHPValue($encrypted, $this->platform);

        $this->assertSame($original, $decrypted);
    }

    public function testHandlesUnicodeCharacters(): void
    {
        $original = 'こんにちは世界 🌍 émoji';

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

    public function testRequiresSQLCommentHintReturnsTrue(): void
    {
        $this->assertTrue($this->type->requiresSQLCommentHint($this->platform));
    }

    public function testConvertToDatabaseValueCastsToString(): void
    {
        // Numbers should be cast to string before encryption
        $result = $this->type->convertToDatabaseValue(12345, $this->platform);

        $this->assertNotNull($result);
        $this->assertStringStartsWith('ENC$1$', $result);

        $decrypted = $this->type->convertToPHPValue($result, $this->platform);
        $this->assertSame('12345', $decrypted);
    }

    public function testThrowsExceptionWhenEncryptorNotInitialized(): void
    {
        // Reset the encryptor
        $reflection = new \ReflectionClass(AbstractEncryptedType::class);
        $property = $reflection->getProperty('encryptor');
        $property->setValue(null, null);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Encryptor not initialized');

        $this->type->convertToDatabaseValue('test', $this->platform);
    }
}
