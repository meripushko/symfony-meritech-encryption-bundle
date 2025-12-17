<?php

namespace Meritech\EncryptionBundle\Crypto;

class KeyProvider
{
    private ?string $currentKey = null; // binary

    /**
     * @param string      $keyEnv     the key from env (supports base64:/hex: prefixes) resolved by Symfony env processor
     * @param string|null $currentKid optional current key id for rotation
     * @param array       $keys       optional map of kid => key string (same encoding as $keyEnv)
     */
    public function __construct(
        private readonly string $keyEnv,
        private readonly ?string $currentKid = null,
        private readonly array $keys = [],
    ) {
    }

    public function getCurrentKey(): string
    {
        if (null === $this->currentKey) {
            $this->currentKey = $this->parseKey($this->keyEnv);
        }

        return $this->currentKey;
    }

    public function getCurrentKid(): ?string
    {
        return $this->currentKid;
    }

    public function getKeyForKid(?string $kid): string
    {
        if (null === $kid) {
            return $this->getCurrentKey();
        }
        if (!array_key_exists($kid, $this->keys)) {
            // Fallback to current key
            return $this->getCurrentKey();
        }

        return $this->parseKey($this->keys[$kid]);
    }

    private function parseKey(string $raw): string
    {
        $bin = null;
        if (str_starts_with($raw, 'base64:')) {
            $bin = base64_decode(substr($raw, 7), true);
        } elseif (str_starts_with($raw, 'hex:')) {
            $hex = substr($raw, 4);
            $bin = hex2bin($hex);
        } else {
            $bin = $raw;
        }
        if (false === $bin || null === $bin) {
            throw new \InvalidArgumentException('Invalid encryption key encoding.');
        }
        if (32 !== strlen($bin)) {
            throw new \InvalidArgumentException('AES-256-GCM key must be exactly 32 bytes.');
        }

        return $bin;
    }
}
