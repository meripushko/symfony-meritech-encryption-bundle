<?php

declare(strict_types=1);

namespace Meritech\EncryptionBundle;

use Meritech\EncryptionBundle\Crypto\AesGcmEncryptor;
use Meritech\EncryptionBundle\Crypto\DeterministicEncryptor;
use Meritech\EncryptionBundle\DBAL\Type\AbstractEncryptedType;
use Meritech\EncryptionBundle\DependencyInjection\MeritechEncryptionExtension;
use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

final class EncryptionBundle extends AbstractBundle
{
    private ?ExtensionInterface $extension = null;

    public function getContainerExtension(): ?ExtensionInterface
    {
        if (null === $this->extension) {
            $this->extension = new MeritechEncryptionExtension();
        }

        return $this->extension;
    }

    public function boot(): void
    {
        parent::boot();

        // Inject encryptors into DBAL types (they're instantiated before container boots)
        $container = $this->container;

        if (null !== $container && $container->has('meritech_encryption.encryptor')) {
            /** @var AesGcmEncryptor $encryptor */
            $encryptor = $container->get('meritech_encryption.encryptor');
            AbstractEncryptedType::setEncryptor($encryptor);
        }

        if (null !== $container && $container->has('meritech_encryption.deterministic_encryptor')) {
            /** @var DeterministicEncryptor $deterministicEncryptor */
            $deterministicEncryptor = $container->get('meritech_encryption.deterministic_encryptor');
            AbstractEncryptedType::setDeterministicEncryptor($deterministicEncryptor);
        }
    }
}
