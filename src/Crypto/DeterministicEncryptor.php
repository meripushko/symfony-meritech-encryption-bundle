<?php

declare(strict_types=1);

namespace Meritech\EncryptionBundle\Crypto;

use Meritech\EncryptionBundle\Exception\DecryptionException;
use Meritech\EncryptionBundle\Exception\EncryptionException;

/**
 * Deterministic encryption using AES-256-GCM with HMAC-derived IV.
 *
 * WARNING: Deterministic encryption leaks equality - use only when
 * you need exact-match searchability and understand the trade-offs.
 *
 * Same plaintext + same key = same ciphertext (allows equality comparisons).
 */
final readonly class DeterministicEncryptor implements EncryptorInterface
{
    private const CIPHER = 'aes-256-gcm';
    private const IV_LENGTH = 12;
    private const TAG_LENGTH = 16;

    public function __construct(
        private KeyProviderInterface $keyProvider,
        private string $prefix = 'DET$1$',
        private ?string $aad = null,
    ) {
    }

    public function encrypt(string $plaintext): string
    {
        $key = $this->keyProvider->getCurrentKey();
        $kid = $this->keyProvider->getCurrentKeyId();

        // Derive deterministic IV from plaintext using HMAC
        // Use separate key derivation for IV to avoid related-key attacks
        $ivKey = hash('sha256', $key.':iv-derivation', binary: true);
        $iv = substr(hash_hmac('sha256', $plaintext, $ivKey, binary: true), 0, self::IV_LENGTH);

        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $this->aad ?? '',
            self::TAG_LENGTH
        );

        if (false === $ciphertext) {
            throw new EncryptionException('Encryption failed: '.openssl_error_string());
        }

        $kidBytes = $kid ?? '';
        $kidLen = chr(strlen($kidBytes));

        $blob = $kidLen.$kidBytes.$iv.$tag.$ciphertext;

        return $this->prefix.base64_encode($blob);
    }

    public function decrypt(string $ciphertext): string
    {
        if (!$this->isEncrypted($ciphertext)) {
            throw new DecryptionException('Invalid encrypted format');
        }

        $blob = base64_decode(substr($ciphertext, strlen($this->prefix)), strict: true);

        if (false === $blob) {
            throw new DecryptionException('Invalid base64 encoding');
        }

        $minLength = 1 + self::IV_LENGTH + self::TAG_LENGTH;
        if (strlen($blob) < $minLength) {
            throw new DecryptionException('Ciphertext too short');
        }

        $kidLen = ord($blob[0]);
        $offset = 1;

        if (strlen($blob) < $offset + $kidLen + self::IV_LENGTH + self::TAG_LENGTH) {
            throw new DecryptionException('Invalid envelope structure');
        }

        $kid = $kidLen > 0 ? substr($blob, $offset, $kidLen) : null;
        $offset += $kidLen;

        $iv = substr($blob, $offset, self::IV_LENGTH);
        $offset += self::IV_LENGTH;

        $tag = substr($blob, $offset, self::TAG_LENGTH);
        $offset += self::TAG_LENGTH;

        $ct = substr($blob, $offset);

        $key = $this->keyProvider->getKeyById($kid);

        $plaintext = openssl_decrypt(
            $ct,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $this->aad ?? ''
        );

        if (false === $plaintext) {
            throw new DecryptionException('Decryption failed - authentication failed');
        }

        return $plaintext;
    }

    public function isEncrypted(string $value): bool
    {
        return str_starts_with($value, $this->prefix);
    }
}
