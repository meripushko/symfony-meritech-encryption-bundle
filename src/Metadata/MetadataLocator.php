<?php

namespace Meritech\EncryptionBundle\Metadata;

use Meritech\EncryptionBundle\Attribute\Encrypted;
use ReflectionClass;
use ReflectionProperty;

class MetadataLocator
{
    /** @var array<class-string, array<string, EncryptedProperty>> */
    private array $cache = [];

    /** @var array<class-string, array<string, ReflectionProperty>> */
    private array $refCache = [];

    /**
     * @return array<string, EncryptedProperty>
     */
    public function getEncryptedProperties(string $class): array
    {
        if (isset($this->cache[$class])) {
            return $this->cache[$class];
        }

        $rc = new ReflectionClass($class);
        $props = [];
        $refMap = [];
        foreach ($rc->getProperties() as $prop) {
            $attributes = $prop->getAttributes(Encrypted::class, \ReflectionAttribute::IS_INSTANCEOF);
            if (count($attributes) === 0) {
                continue;
            }
            $instance = $attributes[0]->newInstance();
            $ep = new EncryptedProperty($prop->getName(), $instance->type, $instance->nullable, $instance->deterministic);
            $props[$prop->getName()] = $ep;
            $refMap[$prop->getName()] = $prop;
        }

        $this->cache[$class] = $props;
        $this->refCache[$class] = $refMap;
        return $props;
    }

    public function getReflectionProperty(string $class, string $property): ?ReflectionProperty
    {
        $this->getEncryptedProperties($class); // ensure cache warm
        return $this->refCache[$class][$property] ?? null;
    }
}
