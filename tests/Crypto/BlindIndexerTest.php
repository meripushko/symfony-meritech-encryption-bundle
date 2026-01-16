<?php

declare(strict_types=1);

namespace Meritech\EncryptionBundle\Tests\Crypto;

use Meritech\EncryptionBundle\Crypto\BlindIndexer;
use Meritech\EncryptionBundle\Crypto\KeyProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(BlindIndexer::class)]
final class BlindIndexerTest extends TestCase
{
    private const TEST_KEY = '01234567890123456789012345678901'; // 32 bytes

    private BlindIndexer $indexer;

    protected function setUp(): void
    {
        $keyProvider = new KeyProvider(self::TEST_KEY);
        $this->indexer = new BlindIndexer($keyProvider);
    }

    public function testGenerateReturnsHexString(): void
    {
        $index = $this->indexer->generate('test@example.com', 'User.email');

        $this->assertMatchesRegularExpression('/^[0-9a-f]+$/', $index);
    }

    public function testGenerateIsDeterministic(): void
    {
        $index1 = $this->indexer->generate('test@example.com', 'User.email');
        $index2 = $this->indexer->generate('test@example.com', 'User.email');

        $this->assertSame($index1, $index2);
    }

    public function testGenerateProducesDifferentIndexesForDifferentValues(): void
    {
        $index1 = $this->indexer->generate('alice@example.com', 'User.email');
        $index2 = $this->indexer->generate('bob@example.com', 'User.email');

        $this->assertNotSame($index1, $index2);
    }

    public function testGenerateProducesDifferentIndexesForDifferentContexts(): void
    {
        $value = 'test@example.com';

        $index1 = $this->indexer->generate($value, 'User.email');
        $index2 = $this->indexer->generate($value, 'Contact.email');

        $this->assertNotSame($index1, $index2);
    }

    public function testGenerateDefaultBitsIs64(): void
    {
        $index = $this->indexer->generate('test', 'context');

        // 64 bits = 8 bytes = 16 hex characters
        $this->assertSame(16, strlen($index));
    }

    #[DataProvider('bitsProvider')]
    public function testGenerateWithCustomBits(int $bits, int $expectedHexLength): void
    {
        $index = $this->indexer->generate('test', 'context', $bits);

        $this->assertSame($expectedHexLength, strlen($index));
    }

    /**
     * @return array<string, array{int, int}>
     */
    public static function bitsProvider(): array
    {
        return [
            '16 bits' => [16, 4],
            '32 bits' => [32, 8],
            '64 bits' => [64, 16],
            '128 bits' => [128, 32],
            '256 bits' => [256, 64],
            '24 bits (not byte aligned)' => [24, 6],
            '20 bits (not byte aligned)' => [20, 6], // ceil(20/8) = 3 bytes = 6 hex
        ];
    }

    public function testGenerateThrowsForTooFewBits(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Bits must be between 16 and 256');

        $this->indexer->generate('test', 'context', 8);
    }

    public function testGenerateThrowsForTooManyBits(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Bits must be between 16 and 256');

        $this->indexer->generate('test', 'context', 512);
    }

    public function testGenerateHandlesEmptyValue(): void
    {
        $index = $this->indexer->generate('', 'context');

        $this->assertNotEmpty($index);
        $this->assertMatchesRegularExpression('/^[0-9a-f]+$/', $index);
    }

    public function testGenerateHandlesUnicodeCharacters(): void
    {
        $index = $this->indexer->generate('こんにちは@example.com', 'User.email');

        $this->assertMatchesRegularExpression('/^[0-9a-f]+$/', $index);
        $this->assertSame(16, strlen($index)); // default 64 bits
    }

    public function testNormalizeTrimsWhitespace(): void
    {
        $normalized = $this->indexer->normalize('  hello world  ');

        $this->assertSame('hello world', $normalized);
    }

    public function testNormalizeConvertsToLowercaseByDefault(): void
    {
        $normalized = $this->indexer->normalize('HELLO World');

        $this->assertSame('hello world', $normalized);
    }

    public function testNormalizePreservesCaseWhenRequested(): void
    {
        $normalized = $this->indexer->normalize('HELLO World', caseInsensitive: false);

        $this->assertSame('HELLO World', $normalized);
    }

    public function testNormalizeHandlesUnicode(): void
    {
        $normalized = $this->indexer->normalize('  HÉLLO Wörld  ');

        $this->assertSame('héllo wörld', $normalized);
    }

    public function testDifferentKeysProduceDifferentIndexes(): void
    {
        $keyProvider1 = new KeyProvider('01234567890123456789012345678901');
        $keyProvider2 = new KeyProvider('abcdefghijklmnopqrstuvwxyz012345');

        $indexer1 = new BlindIndexer($keyProvider1);
        $indexer2 = new BlindIndexer($keyProvider2);

        $index1 = $indexer1->generate('test@example.com', 'User.email');
        $index2 = $indexer2->generate('test@example.com', 'User.email');

        $this->assertNotSame($index1, $index2);
    }

    public function testCustomAlgorithm(): void
    {
        $keyProvider = new KeyProvider(self::TEST_KEY);
        $indexer256 = new BlindIndexer($keyProvider, 'sha256');
        $indexer384 = new BlindIndexer($keyProvider, 'sha384');

        // Same input, different algorithms should produce different results
        // (though truncated to same bits, still different due to different hash)
        $index256 = $indexer256->generate('test', 'context', 128);
        $index384 = $indexer384->generate('test', 'context', 128);

        $this->assertNotSame($index256, $index384);
    }

    public function testCustomDefaultBits(): void
    {
        $keyProvider = new KeyProvider(self::TEST_KEY);
        $indexer = new BlindIndexer($keyProvider, 'sha256', 128);

        $index = $indexer->generate('test', 'context');

        // 128 bits = 16 bytes = 32 hex characters
        $this->assertSame(32, strlen($index));
    }

    public function testMaskingForNonByteAlignedBits(): void
    {
        // For non-byte-aligned bit counts, the last byte should be masked
        // Test that different values with same prefix don't collide due to masking
        $keyProvider = new KeyProvider(self::TEST_KEY);
        $indexer = new BlindIndexer($keyProvider);

        // Use 20 bits (not byte aligned)
        $index1 = $indexer->generate('value1', 'context', 20);
        $index2 = $indexer->generate('value2', 'context', 20);

        $this->assertNotSame($index1, $index2);
    }
}
