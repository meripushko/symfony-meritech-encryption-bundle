<?php

declare(strict_types=1);

namespace Meritech\EncryptionBundle\Tests\Crypto;

use Meritech\EncryptionBundle\Crypto\AesGcmEncryptor;
use Meritech\EncryptionBundle\Crypto\KeyProvider;
use Meritech\EncryptionBundle\Exception\DecryptionException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(AesGcmEncryptor::class)]
final class AesGcmEncryptorTest extends TestCase
{
    private const TEST_KEY = '01234567890123456789012345678901'; // 32 bytes

    private AesGcmEncryptor $encryptor;
    private KeyProvider $keyProvider;

    protected function setUp(): void
    {
        $this->keyProvider = new KeyProvider(self::TEST_KEY, 'test-key');
        $this->encryptor = new AesGcmEncryptor($this->keyProvider);
    }

    public function testEncryptReturnsStringWithPrefix(): void
    {
        $encrypted = $this->encryptor->encrypt('hello world');

        $this->assertStringStartsWith('ENC$1$', $encrypted);
    }

    public function testEncryptAndDecryptRoundTrip(): void
    {
        $plaintext = 'hello world';

        $encrypted = $this->encryptor->encrypt($plaintext);
        $decrypted = $this->encryptor->decrypt($encrypted);

        $this->assertSame($plaintext, $decrypted);
    }

    public function testEncryptProducesDifferentOutputsForSamePlaintext(): void
    {
        $plaintext = 'hello world';

        $encrypted1 = $this->encryptor->encrypt($plaintext);
        $encrypted2 = $this->encryptor->encrypt($plaintext);

        // Randomized encryption should produce different ciphertexts
        $this->assertNotSame($encrypted1, $encrypted2);
    }

    public function testEncryptHandlesEmptyString(): void
    {
        $encrypted = $this->encryptor->encrypt('');
        $decrypted = $this->encryptor->decrypt($encrypted);

        $this->assertSame('', $decrypted);
    }

    public function testEncryptHandlesUnicodeCharacters(): void
    {
        $plaintext = 'こんにちは世界 🌍 émoji';

        $encrypted = $this->encryptor->encrypt($plaintext);
        $decrypted = $this->encryptor->decrypt($encrypted);

        $this->assertSame($plaintext, $decrypted);
    }

    public function testEncryptHandlesLargeData(): void
    {
        $plaintext = str_repeat('a', 1_000_000); // 1MB

        $encrypted = $this->encryptor->encrypt($plaintext);
        $decrypted = $this->encryptor->decrypt($encrypted);

        $this->assertSame($plaintext, $decrypted);
    }

    public function testDecryptWithInvalidPrefixThrowsException(): void
    {
        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessage('Invalid encrypted format');

        $this->encryptor->decrypt('invalid-data');
    }

    public function testDecryptWithInvalidBase64ThrowsException(): void
    {
        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessage('Invalid base64 encoding');

        $this->encryptor->decrypt('ENC$1$not-valid-base64!!!');
    }

    public function testDecryptWithTooShortDataThrowsException(): void
    {
        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessage('Ciphertext too short');

        $this->encryptor->decrypt('ENC$1$'.base64_encode('short'));
    }

    public function testDecryptWithTamperedDataThrowsException(): void
    {
        $encrypted = $this->encryptor->encrypt('hello world');

        // Tamper with the ciphertext
        $tampered = substr($encrypted, 0, -5).'XXXXX';

        $this->expectException(DecryptionException::class);

        $this->encryptor->decrypt($tampered);
    }

    public function testIsEncryptedReturnsTrueForEncryptedData(): void
    {
        $encrypted = $this->encryptor->encrypt('test');

        $this->assertTrue($this->encryptor->isEncrypted($encrypted));
    }

    public function testIsEncryptedReturnsFalseForPlaintext(): void
    {
        $this->assertFalse($this->encryptor->isEncrypted('plain text'));
    }

    public function testIsEncryptedReturnsFalseForEmptyString(): void
    {
        $this->assertFalse($this->encryptor->isEncrypted(''));
    }

    public function testCustomPrefixIsUsed(): void
    {
        $encryptor = new AesGcmEncryptor($this->keyProvider, 'CUSTOM$');

        $encrypted = $encryptor->encrypt('test');

        $this->assertStringStartsWith('CUSTOM$', $encrypted);
    }

    public function testEncryptionWithAadSucceeds(): void
    {
        $encryptor = new AesGcmEncryptor($this->keyProvider, 'ENC$1$', 'additional-data');

        $plaintext = 'secret message';
        $encrypted = $encryptor->encrypt($plaintext);
        $decrypted = $encryptor->decrypt($encrypted);

        $this->assertSame($plaintext, $decrypted);
    }

    public function testDecryptionWithWrongAadFails(): void
    {
        $encryptor1 = new AesGcmEncryptor($this->keyProvider, 'ENC$1$', 'aad-1');
        $encryptor2 = new AesGcmEncryptor($this->keyProvider, 'ENC$1$', 'aad-2');

        $encrypted = $encryptor1->encrypt('secret');

        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessage('authentication failed');

        $encryptor2->decrypt($encrypted);
    }

    public function testKeyRotationDecryption(): void
    {
        $oldKey = 'abcdefghijklmnopqrstuvwxyz012345';
        $newKey = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345';

        // Encrypt with old key
        $oldKeyProvider = new KeyProvider($oldKey, 'key-v1');
        $oldEncryptor = new AesGcmEncryptor($oldKeyProvider);
        $encrypted = $oldEncryptor->encrypt('secret data');

        // Decrypt with new key provider that has old key in rotated keys
        $newKeyProvider = new KeyProvider(
            $newKey,
            'key-v2',
            ['key-v1' => $oldKey]
        );
        $newEncryptor = new AesGcmEncryptor($newKeyProvider);
        $decrypted = $newEncryptor->decrypt($encrypted);

        $this->assertSame('secret data', $decrypted);
    }

    public function testEncryptionWithNoKeyIdStillWorks(): void
    {
        $keyProvider = new KeyProvider(self::TEST_KEY); // No key ID
        $encryptor = new AesGcmEncryptor($keyProvider);

        $plaintext = 'test message';
        $encrypted = $encryptor->encrypt($plaintext);
        $decrypted = $encryptor->decrypt($encrypted);

        $this->assertSame($plaintext, $decrypted);
    }
}
