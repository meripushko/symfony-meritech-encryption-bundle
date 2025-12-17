<?php

namespace Meritech\EncryptionBundle\Crypto;

interface EncryptorInterface
{
    /** Returns true if the value is an encrypted envelope. */
    public function isEncrypted(mixed $value): bool;

    /**
     * Encrypt a value (string or array) and return a versioned envelope string.
     * $type: 'string' or 'json' to guide serialization.
     */
    public function encryptMixed(mixed $value, string $type): string;

    /** Decrypt an envelope string back to original type (string or array). */
    public function decryptToType(string $ciphertext): mixed;
}
