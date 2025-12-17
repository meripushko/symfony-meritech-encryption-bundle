<?php

namespace Meritech\EncryptionBundle\Attribute;

use Attribute;

#[Attribute(Attribute::TARGET_PROPERTY)]
class Encrypted
{
    /**
     * @param string $type   'string' or 'json'
     * @param bool   $nullable Whether null values are allowed (nulls are not encrypted)
     * @param bool   $deterministic If true, indicates desire for deterministic encryption (not recommended for GCM). Currently advisory only.
     */
    public function __construct(
        public string $type = 'string',
        public bool $nullable = true,
        public bool $deterministic = false,
    ) {
        if (!in_array($this->type, ['string', 'json'], true)) {
            throw new \InvalidArgumentException('Encrypted attribute type must be "string" or "json"');
        }
    }
}
