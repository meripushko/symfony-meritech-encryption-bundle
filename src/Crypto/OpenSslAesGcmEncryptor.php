<?php

namespace Meritech\EncryptionBundle\Crypto;

class OpenSslAesGcmEncryptor implements EncryptorInterface
{
    public function __construct(
        private readonly KeyProvider $keyProvider,
        private readonly string $prefix = 'ENC.',
        private readonly ?string $aad = null,
    ) {
    }

    public function isEncrypted(mixed $value): bool
    {
        return is_string($value) && str_starts_with($value, $this->prefix);
    }

    public function encryptMixed(mixed $value, string $type): string
    {
        $plaintext = $this->normalizePlaintext($value, $type);

        $iv = random_bytes(12); // 96-bit nonce for GCM
        $tag = '';
        $key = $this->keyProvider->getCurrentKey();
        $kid = $this->keyProvider->getCurrentKid();

        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $this->aad
        );
        if ($ciphertext === false) {
            throw new \RuntimeException('Encryption failed.');
        }

        $envelope = [
            'v' => 1,
            'alg' => 'aes-256-gcm',
            'iv' => base64_encode($iv),
            'tag' => base64_encode($tag),
            'ct' => base64_encode($ciphertext),
            'typ' => $type === 'json' ? 'json' : 'plain',
        ];
        if ($kid !== null) {
            $envelope['kid'] = $kid;
        }

        $json = json_encode($envelope, JSON_THROW_ON_ERROR);
        return $this->prefix . $json;
    }

    public function decryptToType(string $ciphertext): mixed
    {
        if (!$this->isEncrypted($ciphertext)) {
            return $ciphertext;
        }
        $json = substr($ciphertext, strlen($this->prefix));
        $env = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

        $iv = base64_decode($env['iv'] ?? '', true);
        $tag = base64_decode($env['tag'] ?? '', true);
        $ct = base64_decode($env['ct'] ?? '', true);

        if ($iv === false || $tag === false || $ct === false) {
            throw new \RuntimeException('Invalid envelope encoding.');
        }

        $key = $this->keyProvider->getKeyForKid($env['kid'] ?? null);

        $plaintext = openssl_decrypt(
            $ct,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $this->aad
        );
        if ($plaintext === false) {
            throw new \RuntimeException('Decryption failed.');
        }

        $typ = $env['typ'] ?? 'plain';
        if ($typ === 'json') {
            return json_decode($plaintext, true, 512, JSON_THROW_ON_ERROR);
        }

        return $plaintext;
    }

    private function normalizePlaintext(mixed $value, string $type): string
    {
        if ($value === null) {
            // Represent null as empty string; attribute's nullable controls whether we encrypt or skip
            return '';
        }
        if ($type === 'json') {
            return json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
        }
        return is_string($value) ? $value : (string) $value;
    }
}
