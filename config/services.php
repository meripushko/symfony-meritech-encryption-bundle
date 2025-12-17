<?php

namespace Symfony\Component\DependencyInjection\Loader\Configurator;

use Meritech\EncryptionBundle\Crypto\OpenSslAesGcmEncryptor;
use Meritech\EncryptionBundle\Crypto\KeyProvider;
use Meritech\EncryptionBundle\Doctrine\EncryptedSubscriber;
use Meritech\EncryptionBundle\Metadata\MetadataLocator;

return function (ContainerConfigurator $config) {
    $services = $config->services();
    $services->defaults()->autowire()->autoconfigure();

    $services->set(MetadataLocator::class)->public();

    $services->set(KeyProvider::class)
        ->arg('$keyEnv', '%env(resolve:ENCRYPTION_KEY)%')
        ->arg('$currentKid', '%meritech_encryption.current_kid%')
        ->arg('$keys', '%meritech_encryption.keys%');

    $services->set(OpenSslAesGcmEncryptor::class)
        ->arg('$keyProvider', service(KeyProvider::class))
        ->arg('$prefix', '%meritech_encryption.prefix%')
        ->arg('$aad', '%meritech_encryption.aad%')
        ->public();

    $services->set(EncryptedSubscriber::class)
        ->arg('$metadataLocator', service(MetadataLocator::class))
        ->arg('$encryptor', service(OpenSslAesGcmEncryptor::class))
        ->arg('$excludedEntities', '%meritech_encryption.excluded_entities%')
        ->tag('doctrine.event_subscriber');
};
