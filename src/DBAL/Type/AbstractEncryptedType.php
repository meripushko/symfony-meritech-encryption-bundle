<?php

declare(strict_types=1);

namespace Meritech\EncryptionBundle\DBAL\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Type;
use Meritech\EncryptionBundle\Crypto\EncryptorInterface;

abstract class AbstractEncryptedType extends Type
{
    protected static ?EncryptorInterface $encryptor = null;
    protected static ?EncryptorInterface $deterministicEncryptor = null;

    protected bool $deterministic = false;

    public static function setEncryptor(EncryptorInterface $encryptor): void
    {
        self::$encryptor = $encryptor;
    }

    public static function setDeterministicEncryptor(EncryptorInterface $encryptor): void
    {
        self::$deterministicEncryptor = $encryptor;
    }

    protected function getEncryptor(): EncryptorInterface
    {
        $encryptor = $this->deterministic
            ? self::$deterministicEncryptor
            : self::$encryptor;

        if (null === $encryptor) {
            throw new \LogicException('Encryptor not initialized. Did you forget to boot EncryptionBundle?');
        }

        return $encryptor;
    }

    public function convertToDatabaseValue(mixed $value, AbstractPlatform $platform): ?string
    {
        if (null === $value) {
            return null;
        }

        $stringValue = $this->serializeForEncryption($value);

        // Skip if already encrypted (idempotent)
        if ($this->getEncryptor()->isEncrypted($stringValue)) {
            return $stringValue;
        }

        return $this->getEncryptor()->encrypt($stringValue);
    }

    public function convertToPHPValue(mixed $value, AbstractPlatform $platform): mixed
    {
        if (null === $value || '' === $value) {
            return null;
        }

        if (!is_string($value)) {
            throw new \InvalidArgumentException('Expected string from database');
        }

        // Handle unencrypted values (migration scenario)
        if (!$this->getEncryptor()->isEncrypted($value)) {
            return $this->deserializeFromDecryption($value);
        }

        $decrypted = $this->getEncryptor()->decrypt($value);

        return $this->deserializeFromDecryption($decrypted);
    }

    public function requiresSQLCommentHint(AbstractPlatform $platform): bool
    {
        return true;
    }

    /**
     * Serialize PHP value to string for encryption.
     */
    abstract protected function serializeForEncryption(mixed $value): string;

    /**
     * Deserialize decrypted string to PHP value.
     */
    abstract protected function deserializeFromDecryption(string $value): mixed;
}
