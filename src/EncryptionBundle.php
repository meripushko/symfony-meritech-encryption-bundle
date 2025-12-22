<?php

namespace Meritech\EncryptionBundle;

use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

/**
 * A Bundle that provides the Encrypted attribute for Doctrine entities.
 * This attribute allows transparent AES-256-GCM encryption and decryption.
 *
 * @author Simeon Meripushkoski <sime.meripushkoski@gmail.com>
 */
class EncryptionBundle extends AbstractBundle
{
}
