<?php

namespace Meritech\EncryptionBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('meritech_encryption');
        $root = $treeBuilder->getRootNode();

        $root
            ->children()
                ->scalarNode('algorithm')->defaultValue('aes-256-gcm')->end()
                ->scalarNode('prefix')->defaultValue('ENC.')->end()
                ->scalarNode('aad')->defaultNull()->end()
                ->booleanNode('fail_open')->defaultFalse()->end()
                ->booleanNode('deterministic')->defaultFalse()->end()
                ->arrayNode('excluded_entities')
                    ->prototype('scalar')->end()
                    ->defaultValue([])
                ->end()
                ->scalarNode('key_env')->defaultValue('ENCRYPTION_KEY')->end()
                ->scalarNode('current_kid')->defaultNull()->end()
                ->arrayNode('keys')
                    ->useAttributeAsKey('kid')
                    ->prototype('scalar')->end()
                    ->defaultValue([])
                ->end()
            ->end();

        return $treeBuilder;
    }
}
