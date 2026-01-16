<?php

declare(strict_types=1);

namespace Meritech\EncryptionBundle\Tests\DBAL\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Meritech\EncryptionBundle\Crypto\DeterministicEncryptor;
use Meritech\EncryptionBundle\Crypto\KeyProvider;
use Meritech\EncryptionBundle\DBAL\Type\AbstractEncryptedType;
use Meritech\EncryptionBundle\DBAL\Type\DeterministicEncryptedStringType;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

#[CoversClass(DeterministicEncryptedStringType::class)]
final class DeterministicEncryptedStringTypeTest extends TestCase
{
    private const TEST_KEY = '01234567890123456789012345678901';

    private DeterministicEncryptedStringType $type;
    private AbstractPlatform&MockObject $platform;
    private DeterministicEncryptor $encryptor;

    protected function setUp(): void
    {
        $this->type = new DeterministicEncryptedStringType();
        $this->platform = $this->createMock(AbstractPlatform::class);

        $keyProvider = new KeyProvider(self::TEST_KEY);
        $this->encryptor = new DeterministicEncryptor($keyProvider);
        AbstractEncryptedType::setDeterministicEncryptor($this->encryptor);
    }

    protected function tearDown(): void
    {
        $reflection = new \ReflectionClass(AbstractEncryptedType::class);
        $property = $reflection->getProperty('deterministicEncryptor');
        $property->setValue(null, null);
    }

    public function testGetNameReturnsCorrectName(): void
    {
        $this->assertSame('encrypted_string_deterministic', $this->type->getName());
    }

    public function testConvertToDatabaseValueEncryptsString(): void
    {
        $result = $this->type->convertToDatabaseValue('hello world', $this->platform);

        $this->assertNotNull($result);
        $this->assertStringStartsWith('DET$1$', $result);
    }

    public function testConvertToDatabaseValueProducesDeterministicOutput(): void
    {
        $result1 = $this->type->convertToDatabaseValue('hello world', $this->platform);
        $result2 = $this->type->convertToDatabaseValue('hello world', $this->platform);

        // Deterministic encryption should produce identical results
        $this->assertSame($result1, $result2);
    }

    public function testConvertToDatabaseValueReturnsNullForNull(): void
    {
        $result = $this->type->convertToDatabaseValue(null, $this->platform);

        $this->assertNull($result);
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

    public function testRoundTripEncryptionDecryption(): void
    {
        $original = 'sensitive data';

        $encrypted = $this->type->convertToDatabaseValue($original, $this->platform);
        $decrypted = $this->type->convertToPHPValue($encrypted, $this->platform);

        $this->assertSame($original, $decrypted);
    }

    public function testDifferentValuesProduceDifferentCiphertexts(): void
    {
        $result1 = $this->type->convertToDatabaseValue('value1', $this->platform);
        $result2 = $this->type->convertToDatabaseValue('value2', $this->platform);

        $this->assertNotSame($result1, $result2);
    }

    public function testUsefulForEqualitySearches(): void
    {
        // This test demonstrates the primary use case for deterministic encryption
        $email = 'user@example.com';

        // Encrypt the same email twice (e.g., for storage and for searching)
        $storedValue = $this->type->convertToDatabaseValue($email, $this->platform);
        $searchValue = $this->type->convertToDatabaseValue($email, $this->platform);

        // They should be identical, allowing WHERE email = $searchValue
        $this->assertSame($storedValue, $searchValue);
    }
}
