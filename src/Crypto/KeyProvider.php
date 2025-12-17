<?php

namespace Meritech\EncryptionBundle\Crypto;

class KeyProvider
{
    private ?string $currentKey = null; // binary

    /**
     * @param string      $keyEnv     The key from env (supports base64:/hex: prefixes) resolved by Symfony env processor.
     * @param string|null $currentKid Optional current key id for rotation.
     * @param array       $keys       Optional map of kid => key string (same encoding as $keyEnv).
     */
    public function __construct(
        private readonly string $keyEnv,
        private readonly ?string $currentKid = null,
        private readonly array $keys = [],
    ) {
    }

    public function getCurrentKey(): string
    {
        if ($this->currentKey === null) {
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
        if ($kid === null) {
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
        if ($bin === false || $bin === null) {
            throw new \InvalidArgumentException('Invalid encryption key encoding.');
        }
        if (strlen($bin) !== 32) {
            throw new \InvalidArgumentException('AES-256-GCM key must be exactly 32 bytes.');
        }
        return $bin;
    }
}
