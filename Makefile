.PHONY: install test phpstan cs-fix cs-check ci clean help

# Default target
help:
	@echo "Available commands:"
	@echo "  make install    - Install dependencies"
	@echo "  make test       - Run PHPUnit tests"
	@echo "  make phpstan    - Run PHPStan static analysis"
	@echo "  make cs-fix     - Fix code style with PHP CS Fixer"
	@echo "  make cs-check   - Check code style (dry-run)"
	@echo "  make ci         - Run all CI checks (test, phpstan, cs-check)"
	@echo "  make clean      - Remove generated files"

# Install dependencies
install:
	composer install

# Run tests
test:
	vendor/bin/phpunit

# Run tests with coverage
test-coverage:
	XDEBUG_MODE=coverage vendor/bin/phpunit --coverage-html=.phpunit.coverage

# Run PHPStan
phpstan:
	vendor/bin/phpstan analyse --configuration=phpstan.neon.dist

# Fix code style
cs-fix:
	vendor/bin/php-cs-fixer fix --config=.php-cs-fixer.dist.php

# Check code style (dry-run)
cs-check:
	vendor/bin/php-cs-fixer fix --dry-run --diff --config=.php-cs-fixer.dist.php

# Run all CI checks
ci: test phpstan cs-check
	@echo "All CI checks passed!"

# Clean generated files
clean:
	rm -rf vendor/
	rm -rf .phpunit.cache/
	rm -rf .phpunit.coverage/
	rm -f .php-cs-fixer.cache
	rm -f composer.lock
