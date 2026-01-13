<?php

declare(strict_types=1);

namespace Meritech\EncryptionBundle\Crypto;

use Meritech\EncryptionBundle\Exception\InvalidKeyException;
use Meritech\EncryptionBundle\Exception\KeyNotFoundException;

final readonly class KeyProvider implements KeyProviderInterface
{
    private const KEY_LENGTH = 32;

    /**
     * @param string               $primaryKey    Current encryption key (base64: or hex: prefix supported)
     * @param string|null          $primaryKeyId  ID for current key
     * @param array<string,string> $rotatedKeys   Old keys for decryption (kid => key)
     * @param string|null          $blindIndexKey Separate key for blind indexes
     */
    public function __construct(
        private string $primaryKey,
        private ?string $primaryKeyId = null,
        private array $rotatedKeys = [],
        private ?string $blindIndexKey = null,
    ) {
    }

    public function getCurrentKey(): string
    {
        return $this->parseKey($this->primaryKey);
    }

    public function getCurrentKeyId(): ?string
    {
        return $this->primaryKeyId;
    }

    public function getKeyById(?string $keyId): string
    {
        if (null === $keyId || $keyId === $this->primaryKeyId) {
            return $this->getCurrentKey();
        }

        if (!isset($this->rotatedKeys[$keyId])) {
            throw new KeyNotFoundException(sprintf("Key ID '%s' not found", $keyId));
        }

        return $this->parseKey($this->rotatedKeys[$keyId]);
    }

    public function getBlindIndexKey(): string
    {
        if (null !== $this->blindIndexKey) {
            return $this->parseKey($this->blindIndexKey);
        }

        return hash('sha256', $this->getCurrentKey().':blind-index', binary: true);
    }

    public function getAllKeyIds(): array
    {
        $ids = array_keys($this->rotatedKeys);

        if (null !== $this->primaryKeyId) {
            array_unshift($ids, $this->primaryKeyId);
        }

        return $ids;
    }

    private function parseKey(string $encoded): string
    {
        $binary = match (true) {
            str_starts_with($encoded, 'base64:') => base64_decode(substr($encoded, 7), strict: true),
            str_starts_with($encoded, 'hex:') => hex2bin(substr($encoded, 4)),
            default => $encoded,
        };

        if (false === $binary || self::KEY_LENGTH !== strlen($binary)) {
            throw new InvalidKeyException(sprintf('Key must be exactly %d bytes for AES-256', self::KEY_LENGTH));
        }

        return $binary;
    }
}
