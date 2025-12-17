<?php

namespace Meritech\EncryptionBundle\Command;

use Doctrine\Persistence\ManagerRegistry;
use Meritech\EncryptionBundle\Crypto\EncryptorInterface;
use Meritech\EncryptionBundle\Metadata\MetadataLocator;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'encryption:reencrypt', description: 'Re-encrypt encrypted properties for an entity class using the current key.')]
class ReencryptCommand extends Command
{
    public function __construct(
        private readonly ManagerRegistry $registry,
        private readonly MetadataLocator $locator,
        private readonly EncryptorInterface $encryptor,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addOption('class', null, InputOption::VALUE_REQUIRED, 'FQCN of entity to process')
             ->addOption('batch-size', null, InputOption::VALUE_OPTIONAL, 'Batch size', 100);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $class = (string) $input->getOption('class');
        if ('' === $class) {
            $output->writeln('<error>--class is required</error>');

            return Command::FAILURE;
        }
        $batchSize = (int) $input->getOption('batch-size');
        $em = $this->registry->getManagerForClass($class);
        if (!$em) {
            $output->writeln('<error>No EntityManager for class</error>');

            return Command::FAILURE;
        }
        $repo = $em->getRepository($class);
        $props = $this->locator->getEncryptedProperties($class);
        if ([] === $props) {
            $output->writeln('<comment>No encrypted properties found on class.</comment>');

            return Command::SUCCESS;
        }

        $count = 0;
        $entities = $repo->findAll();
        foreach ($entities as $entity) {
            foreach ($props as $name => $meta) {
                $rp = $this->locator->getReflectionProperty($class, $name);
                if (null === $rp) {
                    continue;
                }
                $value = $rp->getValue($entity);
                if (null === $value && $meta->nullable) {
                    continue;
                }
                if (is_string($value) && $this->encryptor->isEncrypted($value)) {
                    // Decrypt then re-encrypt with current key/kid
                    try {
                        $plain = $this->encryptor->decryptToType($value);
                        $cipher = $this->encryptor->encryptMixed($plain, $meta->type);
                        $rp->setValue($entity, $cipher);
                    } catch (\Throwable $e) {
                        $output->writeln('<error>Failed to re-encrypt property '.$name.': '.$e->getMessage().'</error>');
                        continue;
                    }
                } else {
                    // Encrypt plaintext if not yet encrypted
                    $cipher = $this->encryptor->encryptMixed($value, $meta->type);
                    $rp->setValue($entity, $cipher);
                }
            }
            $em->persist($entity);
            ++$count;
            if (0 === $count % $batchSize) {
                $em->flush();
                $em->clear();
            }
        }
        $em->flush();

        $output->writeln(sprintf('<info>Processed %d entities.</info>', $count));

        return Command::SUCCESS;
    }
}
