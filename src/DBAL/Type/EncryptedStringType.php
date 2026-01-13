<?php

declare(strict_types=1);

namespace Meritech\EncryptionBundle\DBAL\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;

class EncryptedStringType extends AbstractEncryptedType
{
    public const NAME = 'encrypted_string';

    public function getSQLDeclaration(array $column, AbstractPlatform $platform): string
    {
        // Encrypted strings expand significantly; use TEXT
        return $platform->getClobTypeDeclarationSQL($column);
    }

    public function getName(): string
    {
        return self::NAME;
    }

    protected function serializeForEncryption(mixed $value): string
    {
        return (string) $value;
    }

    protected function deserializeFromDecryption(string $value): string
    {
        return $value;
    }
}
