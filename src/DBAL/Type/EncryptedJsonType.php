<?php

declare(strict_types=1);

namespace Meritech\EncryptionBundle\DBAL\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;

class EncryptedJsonType extends AbstractEncryptedType
{
    public const NAME = 'encrypted_json';

    public function getSQLDeclaration(array $column, AbstractPlatform $platform): string
    {
        return $platform->getClobTypeDeclarationSQL($column);
    }

    public function getName(): string
    {
        return self::NAME;
    }

    protected function serializeForEncryption(mixed $value): string
    {
        return json_encode(
            $value,
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION
        );
    }

    /**
     * @return array<mixed>
     */
    protected function deserializeFromDecryption(string $value): array
    {
        return json_decode($value, associative: true, flags: JSON_THROW_ON_ERROR);
    }
}
