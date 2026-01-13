<?php

declare(strict_types=1);

namespace Meritech\EncryptionBundle\DBAL\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Type;

/**
 * Stores pre-computed blind index values.
 * This is a simple string type - the actual hashing is done at entity level.
 */
class BlindIndexType extends Type
{
    public const NAME = 'blind_index';

    public function getSQLDeclaration(array $column, AbstractPlatform $platform): string
    {
        // Blind indexes are short hex strings (16-64 chars typically)
        $column['length'] ??= 64;

        return $platform->getStringTypeDeclarationSQL($column);
    }

    public function getName(): string
    {
        return self::NAME;
    }

    public function convertToDatabaseValue(mixed $value, AbstractPlatform $platform): ?string
    {
        return $value;
    }

    public function convertToPHPValue(mixed $value, AbstractPlatform $platform): ?string
    {
        return $value;
    }
}
