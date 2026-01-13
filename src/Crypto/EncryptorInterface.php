<?php

declare(strict_types=1);

namespace Meritech\EncryptionBundle\Crypto;

interface EncryptorInterface
{
    /**
     * Encrypt a plaintext string.
     */
    public function encrypt(string $plaintext): string;

    /**
     * Decrypt a ciphertext string.
     */
    public function decrypt(string $ciphertext): string;

    /**
     * Check if a value is already encrypted.
     */
    public function isEncrypted(string $value): bool;
}
