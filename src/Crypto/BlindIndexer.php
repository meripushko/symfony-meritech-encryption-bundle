<?php

declare(strict_types=1);

namespace Meritech\EncryptionBundle\Crypto;

/**
 * Generates HMAC-based blind indexes for searchable encrypted columns.
 *
 * Blind indexes allow WHERE clause equality searches without revealing plaintext.
 * The index is a truncated HMAC - shorter = more collisions = more privacy.
 */
final readonly class BlindIndexer
{
    public function __construct(
        private KeyProviderInterface $keyProvider,
        private string $algorithm = 'sha256',
        private int $defaultBits = 64,
    ) {
    }

    /**
     * Generate a blind index for a plaintext value.
     *
     * @param string   $plaintext The value to index
     * @param string   $context   Context string (e.g., "User.email") for domain separation
     * @param int|null $bits      Output bits (16-256). Lower = more collisions = more privacy.
     *
     * @return string Hex-encoded blind index
     */
    public function generate(string $plaintext, string $context, ?int $bits = null): string
    {
        $bits ??= $this->defaultBits;

        if ($bits < 16 || $bits > 256) {
            throw new \InvalidArgumentException('Bits must be between 16 and 256');
        }

        $key = $this->keyProvider->getBlindIndexKey();

        // Domain separation: include context in HMAC input
        $input = $context."\x00".$plaintext;

        $hash = hash_hmac($this->algorithm, $input, $key, binary: true);

        // Truncate to desired bit length
        $bytes = (int) ceil($bits / 8);
        $truncated = substr($hash, 0, $bytes);

        // If bits not byte-aligned, mask the last byte
        if (0 !== $bits % 8) {
            $mask = (1 << ($bits % 8)) - 1;
            $truncated[-1] = chr(ord($truncated[-1]) & $mask);
        }

        return bin2hex($truncated);
    }

    /**
     * Normalize value before indexing (lowercase, trim, etc.).
     */
    public function normalize(string $value, bool $caseInsensitive = true): string
    {
        $value = trim($value);

        if ($caseInsensitive) {
            $value = mb_strtolower($value, 'UTF-8');
        }

        return $value;
    }
}
