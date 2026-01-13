<?php

declare(strict_types=1);

namespace Meritech\EncryptionBundle\DBAL\Type;

class DeterministicEncryptedStringType extends EncryptedStringType
{
    public const NAME = 'encrypted_string_deterministic';

    protected bool $deterministic = true;

    public function getName(): string
    {
        return self::NAME;
    }
}
