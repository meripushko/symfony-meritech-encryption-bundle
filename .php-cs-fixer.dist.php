<?php

// https://cs.symfony.com/doc/usage.html
// https://cs.symfony.com/doc/rules/index.html oppure https://mlocati.github.io/php-cs-fixer-configurator/#version:3.7

$finder = PhpCsFixer\Finder::create()
    ->exclude('.vscode')
    ->exclude('tools')
    ->exclude('var')
    ->exclude('vendor')
    ->in(__DIR__)
;

$config = new PhpCsFixer\Config();
return $config->setRules([
        '@Symfony' => true,
    ])
    ->setFinder($finder)
;