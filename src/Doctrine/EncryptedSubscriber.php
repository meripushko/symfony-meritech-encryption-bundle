<?php

namespace Meritech\EncryptionBundle\Doctrine;

use Doctrine\Common\EventSubscriber;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Event\OnFlushEventArgs;
use Doctrine\ORM\Event\PostLoadEventArgs;
use Doctrine\ORM\Events;
use Meritech\EncryptionBundle\Crypto\EncryptorInterface;
use Meritech\EncryptionBundle\Metadata\MetadataLocator;

class EncryptedSubscriber implements EventSubscriber
{
    public function __construct(
        private readonly MetadataLocator $metadataLocator,
        private readonly EncryptorInterface $encryptor,
        private readonly array $excludedEntities = [],
    ) {
    }

    public function getSubscribedEvents(): array
    {
        return [
            Events::onFlush,
            Events::postLoad,
        ];
    }

    public function onFlush(OnFlushEventArgs $args): void
    {
        $em = $args->getObjectManager();
        $uow = $em->getUnitOfWork();

        foreach ($uow->getScheduledEntityInsertions() as $entity) {
            $this->encryptEntity($entity, $em);
        }
        foreach ($uow->getScheduledEntityUpdates() as $entity) {
            $this->encryptEntity($entity, $em);
        }
    }

    public function postLoad(PostLoadEventArgs $args): void
    {
        $entity = $args->getObject();
        $class = get_class($entity);
        if (in_array($class, $this->excludedEntities, true)) {
            return;
        }

        $props = $this->metadataLocator->getEncryptedProperties($class);
        if ([] === $props) {
            return;
        }

        foreach ($props as $name => $meta) {
            $rp = $this->metadataLocator->getReflectionProperty($class, $name);
            if (null === $rp) {
                continue;
            }
            $value = $rp->getValue($entity);
            if (null === $value) {
                // Preserve null if allowed
                if ($meta->nullable) {
                    continue;
                }
            }
            if (is_string($value) && !$this->encryptor->isEncrypted($value)) {
                // Loaded plaintext due to raw queries; leave as-is in memory
                continue;
            }
            if (is_string($value) && $this->encryptor->isEncrypted($value)) {
                $decrypted = $this->encryptor->decryptToType($value);
                $rp->setValue($entity, $decrypted);
            }
        }
    }

    private function encryptEntity(object $entity, EntityManagerInterface $em): void
    {
        $class = get_class($entity);
        if (in_array($class, $this->excludedEntities, true)) {
            return;
        }
        $props = $this->metadataLocator->getEncryptedProperties($class);
        if ([] === $props) {
            return;
        }

        $changed = false;
        foreach ($props as $name => $meta) {
            $rp = $this->metadataLocator->getReflectionProperty($class, $name);
            if (null === $rp) {
                continue;
            }
            $value = $rp->getValue($entity);
            if (null === $value) {
                if ($meta->nullable) {
                    continue;
                }
                // Enforce non-null: encode empty
                $value = '';
            }

            // If already encrypted, skip
            if ($this->encryptor->isEncrypted($value)) {
                continue;
            }

            if ('json' === $meta->type && !is_array($value)) {
                // Allow string JSON inputs, decode if possible; else wrap scalar
                if (is_string($value)) {
                    try {
                        $decoded = json_decode($value, true, 512, JSON_THROW_ON_ERROR);
                        $value = $decoded;
                    } catch (\Throwable $e) {
                        // Treat as scalar to be wrapped during normalization
                    }
                }
            }

            $encrypted = $this->encryptor->encryptMixed($value, $meta->type);
            $rp->setValue($entity, $encrypted);
            $changed = true;
        }

        if ($changed) {
            $meta = $em->getClassMetadata($class);
            $em->getUnitOfWork()->recomputeSingleEntityChangeSet($meta, $entity);
        }
    }
}
