<?php

namespace Meritech\EncryptionBundle\Metadata;

class EncryptedProperty
{
    public function __construct(
        public readonly string $name,
        public readonly string $type, // 'string' or 'json'
        public readonly bool $nullable,
        public readonly bool $deterministic,
    ) {
    }
}
