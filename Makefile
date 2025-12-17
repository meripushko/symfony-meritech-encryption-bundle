cs_fixer_install:
	mkdir -p tools/php-cs-fixer
	composer require --dev --working-dir=tools/php-cs-fixer friendsofphp/php-cs-fixer

cs_fixer_configure:
	rsync -pavz hooks/ .git/hooks/
	sudo chmod -R 777 .git/hooks/

cs_fixer:
	tools/php-cs-fixer/vendor/bin/php-cs-fixer fix --config=.php-cs-fixer.dist.php