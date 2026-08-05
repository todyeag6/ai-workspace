FROM php:8.3-cli

RUN apt-get update && apt-get install -y --no-install-recommends \
      git unzip default-mysql-client \
 && rm -rf /var/lib/apt/lists/* \
 && docker-php-ext-install pdo_mysql \
 && printf "\n" | pecl install redis \
 && docker-php-ext-enable redis

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /app
