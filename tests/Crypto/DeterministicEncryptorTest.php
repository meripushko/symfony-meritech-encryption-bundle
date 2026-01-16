<?php

declare(strict_types=1);

namespace Meritech\EncryptionBundle\Tests\Crypto;

use Meritech\EncryptionBundle\Crypto\DeterministicEncryptor;
use Meritech\EncryptionBundle\Crypto\KeyProvider;
use Meritech\EncryptionBundle\Exception\DecryptionException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(DeterministicEncryptor::class)]
final class DeterministicEncryptorTest extends TestCase
{
    private const TEST_KEY = '01234567890123456789012345678901'; // 32 bytes

    private DeterministicEncryptor $encryptor;
    private KeyProvider $keyProvider;

    protected function setUp(): void
    {
        $this->keyProvider = new KeyProvider(self::TEST_KEY, 'test-key');
        $this->encryptor = new DeterministicEncryptor($this->keyProvider);
    }

    public function testEncryptReturnsStringWithPrefix(): void
    {
        $encrypted = $this->encryptor->encrypt('hello world');

        $this->assertStringStartsWith('DET$1$', $encrypted);
    }

    public function testEncryptAndDecryptRoundTrip(): void
    {
        $plaintext = 'hello world';

        $encrypted = $this->encryptor->encrypt($plaintext);
        $decrypted = $this->encryptor->decrypt($encrypted);

        $this->assertSame($plaintext, $decrypted);
    }

    public function testEncryptProducesSameOutputForSamePlaintext(): void
    {
        $plaintext = 'hello world';

        $encrypted1 = $this->encryptor->encrypt($plaintext);
        $encrypted2 = $this->encryptor->encrypt($plaintext);

        // Deterministic encryption should produce identical ciphertexts
        $this->assertSame($encrypted1, $encrypted2);
    }

    public function testDifferentPlaintextsProduceDifferentCiphertexts(): void
    {
        $encrypted1 = $this->encryptor->encrypt('hello');
        $encrypted2 = $this->encryptor->encrypt('world');

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

        $this->encryptor->decrypt('DET$1$not-valid-base64!!!');
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

    public function testCustomPrefixIsUsed(): void
    {
        $encryptor = new DeterministicEncryptor($this->keyProvider, 'CUSTOM$');

        $encrypted = $encryptor->encrypt('test');

        $this->assertStringStartsWith('CUSTOM$', $encrypted);
    }

    public function testDifferentKeysProduceDifferentCiphertexts(): void
    {
        $keyProvider1 = new KeyProvider('01234567890123456789012345678901');
        $keyProvider2 = new KeyProvider('abcdefghijklmnopqrstuvwxyz012345');

        $encryptor1 = new DeterministicEncryptor($keyProvider1);
        $encryptor2 = new DeterministicEncryptor($keyProvider2);

        $plaintext = 'test message';
        $encrypted1 = $encryptor1->encrypt($plaintext);
        $encrypted2 = $encryptor2->encrypt($plaintext);

        $this->assertNotSame($encrypted1, $encrypted2);
    }

    public function testEncryptionWithAadSucceeds(): void
    {
        $encryptor = new DeterministicEncryptor($this->keyProvider, 'DET$1$', 'additional-data');

        $plaintext = 'secret message';
        $encrypted = $encryptor->encrypt($plaintext);
        $decrypted = $encryptor->decrypt($encrypted);

        $this->assertSame($plaintext, $decrypted);
    }

    public function testDecryptionWithWrongAadFails(): void
    {
        $encryptor1 = new DeterministicEncryptor($this->keyProvider, 'DET$1$', 'aad-1');
        $encryptor2 = new DeterministicEncryptor($this->keyProvider, 'DET$1$', 'aad-2');

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
        $oldEncryptor = new DeterministicEncryptor($oldKeyProvider);
        $encrypted = $oldEncryptor->encrypt('secret data');

        // Decrypt with new key provider that has old key in rotated keys
        $newKeyProvider = new KeyProvider(
            $newKey,
            'key-v2',
            ['key-v1' => $oldKey]
        );
        $newEncryptor = new DeterministicEncryptor($newKeyProvider);
        $decrypted = $newEncryptor->decrypt($encrypted);

        $this->assertSame('secret data', $decrypted);
    }

    public function testDeterministicOutputIsConsistentAcrossInstances(): void
    {
        // Create two separate encryptor instances
        $encryptor1 = new DeterministicEncryptor(new KeyProvider(self::TEST_KEY, 'key'));
        $encryptor2 = new DeterministicEncryptor(new KeyProvider(self::TEST_KEY, 'key'));

        $plaintext = 'consistent encryption';
        $encrypted1 = $encryptor1->encrypt($plaintext);
        $encrypted2 = $encryptor2->encrypt($plaintext);

        $this->assertSame($encrypted1, $encrypted2);
    }
}
