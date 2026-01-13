<?php

declare(strict_types=1);

namespace Meritech\EncryptionBundle\Attribute;

use Attribute;

/**
 * Marks a property for blind index generation.
 *
 * Apply this attribute to properties that need searchable encryption.
 * The blind index will be stored in a separate column specified by indexProperty.
 */
#[\Attribute(\Attribute::TARGET_PROPERTY | \Attribute::IS_REPEATABLE)]
final readonly class BlindIndex
{
    /**
     * @param string      $indexProperty   The property name where the blind index is stored
     * @param string|null $context         Context for HMAC domain separation (defaults to "ClassName.propertyName")
     * @param int         $bits            Output bits (16-256). Lower = more privacy, more collisions.
     * @param bool        $caseInsensitive Whether to lowercase before hashing
     */
    public function __construct(
        public string $indexProperty,
        public ?string $context = null,
        public int $bits = 64,
        public bool $caseInsensitive = true,
    ) {
    }
}
