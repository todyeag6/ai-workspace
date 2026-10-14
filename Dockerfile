FROM php:8.3-cli

RUN apt-get update && apt-get install -y --no-install-recommends \
      git unzip default-mysql-client \
 && rm -rf /var/lib/apt/lists/* \
 && docker-php-ext-install pdo_mysql \
 && printf "\n" | pecl install redis \
 && docker-php-ext-enable redis

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# MySQL 8 auto-generates a self-signed dev cert. Debian's `default-mysql-client`
# is the MariaDB client, which verifies the server cert by default and would
# otherwise fail with "TLS/SSL error: self-signed certificate in certificate
# chain". Dev-only image, local server -- skip verification so `mysql` works
# without per-invocation flags.
RUN printf '[client]\nssl-verify-server-cert=0\n' > /etc/mysql/my.cnf

# SEC-009: stop advertising the PHP version. expose_php is INI_SYSTEM (php.ini
# only -- it cannot be set at runtime), so it is baked into the image. Without
# this every response carries "X-Powered-By: PHP/8.3.33", handing an attacker the
# exact version to match exploits against.
RUN printf 'expose_php=Off\n' > /usr/local/etc/php/conf.d/security.ini

WORKDIR /app
