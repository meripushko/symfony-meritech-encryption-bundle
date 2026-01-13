<?php

declare(strict_types=1);

namespace Meritech\EncryptionBundle\DBAL\Type;

class EncryptedTextType extends EncryptedStringType
{
    public const NAME = 'encrypted_text';

    public function getName(): string
    {
        return self::NAME;
    }
}
