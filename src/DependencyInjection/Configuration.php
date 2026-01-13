<?php

declare(strict_types=1);

namespace Meritech\EncryptionBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

final class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('meritech_encryption');
        $root = $treeBuilder->getRootNode();

        $root
            ->children()
                // Primary key configuration
                ->arrayNode('key')
                    ->isRequired()
                    ->children()
                        ->scalarNode('value')
                            ->isRequired()
                            ->info('Primary encryption key (env var recommended). Prefix: base64: or hex:')
                            ->example('%env(ENCRYPTION_KEY)%')
                        ->end()
                        ->scalarNode('id')
                            ->defaultNull()
                            ->info('Key identifier for rotation tracking')
                            ->example('k1')
                        ->end()
                    ->end()
                ->end()

                // Rotated keys for decryption
                ->arrayNode('rotated_keys')
                    ->useAttributeAsKey('id')
                    ->scalarPrototype()->end()
                    ->info('Previous keys for decrypting old data (id => key)')
                ->end()

                // Separate blind index key (recommended)
                ->scalarNode('blind_index_key')
                    ->defaultNull()
                    ->info('Separate key for blind indexes. If null, derived from primary key.')
                ->end()

                // Envelope prefixes
                ->scalarNode('prefix')
                    ->defaultValue('ENC$1$')
                    ->info('Prefix for randomized encrypted values')
                ->end()

                ->scalarNode('deterministic_prefix')
                    ->defaultValue('DET$1$')
                    ->info('Prefix for deterministic encrypted values')
                ->end()

                // Additional authenticated data
                ->scalarNode('aad')
                    ->defaultNull()
                    ->info('Additional authenticated data for GCM mode')
                ->end()

                // Blind index defaults
                ->arrayNode('blind_index')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->integerNode('default_bits')
                            ->defaultValue(64)
                            ->min(16)
                            ->max(256)
                            ->info('Default output bits for blind indexes')
                        ->end()
                        ->enumNode('algorithm')
                            ->values(['sha256', 'sha384', 'sha512'])
                            ->defaultValue('sha256')
                        ->end()
                    ->end()
                ->end()

                // DBAL type registration
                ->arrayNode('types')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->booleanNode('encrypted_string')->defaultTrue()->end()
                        ->booleanNode('encrypted_text')->defaultTrue()->end()
                        ->booleanNode('encrypted_json')->defaultTrue()->end()
                        ->booleanNode('encrypted_string_deterministic')->defaultTrue()->end()
                        ->booleanNode('blind_index')->defaultTrue()->end()
                    ->end()
                ->end()
            ->end();

        return $treeBuilder;
    }
}
