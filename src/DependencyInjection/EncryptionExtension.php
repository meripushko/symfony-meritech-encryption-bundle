<?php

namespace Meritech\EncryptionBundle\DependencyInjection;

use Meritech\EncryptionBundle\Crypto\KeyProvider;
use Meritech\EncryptionBundle\Crypto\OpenSslAesGcmEncryptor;
use Meritech\EncryptionBundle\Doctrine\EncryptedSubscriber;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\Config\FileLocator;

class EncryptionExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container)
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        $loader = new PhpFileLoader($container, new FileLocator(__DIR__ . '/../../config'));
        $loader->load('services.php');

        // Bind configurable args
        if (isset($config['current_kid'])) {
            $container->setParameter('meritech_encryption.current_kid', $config['current_kid']);
        } else {
            $container->setParameter('meritech_encryption.current_kid', null);
        }
        $container->setParameter('meritech_encryption.keys', $config['keys'] ?? []);
        $container->setParameter('meritech_encryption.prefix', $config['prefix']);
        $container->setParameter('meritech_encryption.aad', $config['aad']);
        $container->setParameter('meritech_encryption.excluded_entities', $config['excluded_entities']);

        // Update service definitions
        if ($container->hasDefinition(KeyProvider::class)) {
            $def = $container->getDefinition(KeyProvider::class);
            // Note: key_env dynamic env is not supported easily; keep using ENCRYPTION_KEY from services.php
            $def->setArgument('$currentKid', '%meritech_encryption.current_kid%');
            $def->setArgument('$keys', '%meritech_encryption.keys%');
        }
        if ($container->hasDefinition(OpenSslAesGcmEncryptor::class)) {
            $def = $container->getDefinition(OpenSslAesGcmEncryptor::class);
            $def->setArgument('$prefix', '%meritech_encryption.prefix%');
            $def->setArgument('$aad', '%meritech_encryption.aad%');
        }
        if ($container->hasDefinition(EncryptedSubscriber::class)) {
            $def = $container->getDefinition(EncryptedSubscriber::class);
            $def->setArgument('$excludedEntities', '%meritech_encryption.excluded_entities%');
        }
    }
}
