<?php

declare(strict_types=1);

namespace Meritech\EncryptionBundle\Doctrine;

use Doctrine\Bundle\DoctrineBundle\Attribute\AsDoctrineListener;
use Doctrine\ORM\Event\PrePersistEventArgs;
use Doctrine\ORM\Event\PreUpdateEventArgs;
use Doctrine\ORM\Events;
use Meritech\EncryptionBundle\Attribute\BlindIndex;
use Meritech\EncryptionBundle\Crypto\BlindIndexer;

#[AsDoctrineListener(event: Events::prePersist)]
#[AsDoctrineListener(event: Events::preUpdate)]
final readonly class BlindIndexSubscriber
{
    public function __construct(
        private BlindIndexer $blindIndexer,
    ) {
    }

    public function prePersist(PrePersistEventArgs $event): void
    {
        $this->processEntity($event->getObject());
    }

    public function preUpdate(PreUpdateEventArgs $event): void
    {
        $entity = $event->getObject();
        $changeSet = $event->getEntityChangeSet();

        // Only recompute blind indexes for changed properties
        $this->processEntity($entity, array_keys($changeSet));
    }

    /**
     * @param list<string>|null $changedProperties
     */
    private function processEntity(object $entity, ?array $changedProperties = null): void
    {
        $reflection = new \ReflectionClass($entity);

        foreach ($reflection->getProperties() as $property) {
            // Skip if we're updating and this property didn't change
            if (null !== $changedProperties && !in_array($property->getName(), $changedProperties, true)) {
                continue;
            }

            $attributes = $property->getAttributes(BlindIndex::class);

            foreach ($attributes as $attribute) {
                /** @var BlindIndex $config */
                $config = $attribute->newInstance();

                $value = $property->getValue($entity);

                if (null === $value) {
                    $this->setBlindIndexValue($entity, $reflection, $config->indexProperty, null);
                    continue;
                }

                // Normalize the value
                $normalized = $this->blindIndexer->normalize((string) $value, $config->caseInsensitive);

                // Generate context if not provided
                $context = $config->context ?? $this->generateContext($reflection, $property);

                // Compute blind index
                $blindIndex = $this->blindIndexer->generate($normalized, $context, $config->bits);

                // Set the blind index property
                $this->setBlindIndexValue($entity, $reflection, $config->indexProperty, $blindIndex);
            }
        }
    }

    /**
     * @param \ReflectionClass<object> $reflection
     */
    private function setBlindIndexValue(
        object $entity,
        \ReflectionClass $reflection,
        string $propertyName,
        ?string $value,
    ): void {
        $property = $reflection->getProperty($propertyName);
        $property->setValue($entity, $value);
    }

    /**
     * @param \ReflectionClass<object> $class
     */
    private function generateContext(\ReflectionClass $class, \ReflectionProperty $property): string
    {
        return $class->getShortName().'.'.$property->getName();
    }
}
