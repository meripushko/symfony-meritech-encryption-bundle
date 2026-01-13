<?php

declare(strict_types=1);

namespace Meritech\EncryptionBundle\Crypto;

interface KeyProviderInterface
{
    /**
     * Get the current encryption key (binary, 32 bytes).
     */
    public function getCurrentKey(): string;

    /**
     * Get current key ID for envelope tagging.
     */
    public function getCurrentKeyId(): ?string;

    /**
     * Get key by ID for decryption.
     */
    public function getKeyById(?string $keyId): string;

    /**
     * Get separate key for blind index generation.
     */
    public function getBlindIndexKey(): string;

    /**
     * Get all key IDs for re-encryption operations.
     *
     * @return list<string>
     */
    public function getAllKeyIds(): array;
}
