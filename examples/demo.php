<?php

require __DIR__.'/../vendor/autoload.php';

use Meritech\EncryptionBundle\Crypto\KeyProvider;
use Meritech\EncryptionBundle\Crypto\OpenSslAesGcmEncryptor;

$keyEnv = getenv('ENCRYPTION_KEY');
if (!$keyEnv) {
    fwrite(STDERR, "ENCRYPTION_KEY env not set. Example: base64:...\n");
    exit(1);
}

$kp = new KeyProvider($keyEnv);
$enc = new OpenSslAesGcmEncryptor($kp);

$plaintext = 'hello-world';
$cipher = $enc->encryptMixed($plaintext, 'string');
$back = $enc->decryptToType($cipher);

echo "String roundtrip: \n";
echo "  cipher: $cipher\n";
echo "  plain:  $back\n\n";

$arr = ['a' => 1, 'b' => 2.5, 'c' => '✓'];
$cipher2 = $enc->encryptMixed($arr, 'json');
$back2 = $enc->decryptToType($cipher2);

echo "JSON roundtrip: \n";
echo "  cipher: $cipher2\n";
echo '  plain:  '.json_encode($back2, JSON_UNESCAPED_UNICODE)."\n";
