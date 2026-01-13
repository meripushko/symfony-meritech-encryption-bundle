<?php

declare(strict_types=1);

namespace Meritech\EncryptionBundle\DependencyInjection;

use Doctrine\DBAL\Types\Type;
use Meritech\EncryptionBundle\Crypto\AesGcmEncryptor;
use Meritech\EncryptionBundle\Crypto\BlindIndexer;
use Meritech\EncryptionBundle\Crypto\DeterministicEncryptor;
use Meritech\EncryptionBundle\Crypto\KeyProvider;
use Meritech\EncryptionBundle\DBAL\Type\BlindIndexType;
use Meritech\EncryptionBundle\DBAL\Type\DeterministicEncryptedStringType;
use Meritech\EncryptionBundle\DBAL\Type\EncryptedJsonType;
use Meritech\EncryptionBundle\DBAL\Type\EncryptedStringType;
use Meritech\EncryptionBundle\DBAL\Type\EncryptedTextType;
use Meritech\EncryptionBundle\Doctrine\BlindIndexSubscriber;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Reference;

final class EncryptionExtension extends Extension
{
    private const TYPE_MAP = [
        'encrypted_string' => EncryptedStringType::class,
        'encrypted_text' => EncryptedTextType::class,
        'encrypted_json' => EncryptedJsonType::class,
        'encrypted_string_deterministic' => DeterministicEncryptedStringType::class,
        'blind_index' => BlindIndexType::class,
    ];

    public function load(array $configs, ContainerBuilder $container): void
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        $this->registerKeyProvider($container, $config);
        $this->registerEncryptors($container, $config);
        $this->registerBlindIndexer($container, $config);
        $this->registerDoctrineSubscriber($container);
        $this->registerDbalTypes($config);
    }

    private function registerKeyProvider(ContainerBuilder $container, array $config): void
    {
        $definition = new Definition(KeyProvider::class);
        $definition->setArguments([
            $config['key']['value'],
            $config['key']['id'],
            $config['rotated_keys'],
            $config['blind_index_key'],
        ]);

        $container->setDefinition('meritech_encryption.key_provider', $definition);
        $container->setAlias(KeyProvider::class, 'meritech_encryption.key_provider');
    }

    private function registerEncryptors(ContainerBuilder $container, array $config): void
    {
        // Randomized encryptor
        $encryptor = new Definition(AesGcmEncryptor::class);
        $encryptor->setArguments([
            new Reference('meritech_encryption.key_provider'),
            $config['prefix'],
            $config['aad'],
        ]);

        $container->setDefinition('meritech_encryption.encryptor', $encryptor);
        $container->setAlias(AesGcmEncryptor::class, 'meritech_encryption.encryptor');

        // Deterministic encryptor
        $deterministicEncryptor = new Definition(DeterministicEncryptor::class);
        $deterministicEncryptor->setArguments([
            new Reference('meritech_encryption.key_provider'),
            $config['deterministic_prefix'],
            $config['aad'],
        ]);

        $container->setDefinition('meritech_encryption.deterministic_encryptor', $deterministicEncryptor);
        $container->setAlias(DeterministicEncryptor::class, 'meritech_encryption.deterministic_encryptor');
    }

    private function registerBlindIndexer(ContainerBuilder $container, array $config): void
    {
        $definition = new Definition(BlindIndexer::class);
        $definition->setArguments([
            new Reference('meritech_encryption.key_provider'),
            $config['blind_index']['algorithm'],
            $config['blind_index']['default_bits'],
        ]);

        $container->setDefinition('meritech_encryption.blind_indexer', $definition);
        $container->setAlias(BlindIndexer::class, 'meritech_encryption.blind_indexer');
    }

    private function registerDoctrineSubscriber(ContainerBuilder $container): void
    {
        $definition = new Definition(BlindIndexSubscriber::class);
        $definition->setArguments([
            new Reference('meritech_encryption.blind_indexer'),
        ]);
        $definition->addTag('doctrine.event_listener', ['event' => 'prePersist']);
        $definition->addTag('doctrine.event_listener', ['event' => 'preUpdate']);

        $container->setDefinition('meritech_encryption.blind_index_subscriber', $definition);
    }

    private function registerDbalTypes(array $config): void
    {
        foreach (self::TYPE_MAP as $name => $class) {
            $configKey = str_replace('encrypted_string_deterministic', 'encrypted_string_deterministic', $name);
            if ($config['types'][$configKey] ?? true) {
                if (!Type::hasType($name)) {
                    Type::addType($name, $class);
                }
            }
        }
    }

    public function getAlias(): string
    {
        return 'meritech_encryption';
    }
}
