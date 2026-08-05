<?php

declare(strict_types=1);

namespace App\Infra;

use InvalidArgumentException;

/**
 * The connection details carried by a PDO MySQL DSN, pulled apart.
 *
 * The backup and restore paths hand credentials to the mysqldump/mysql
 * binaries, which take --host/--port/--user rather than a DSN string, so the
 * DSN has to be decomposed exactly once and in exactly one place. Doing it
 * here rather than in each script keeps the three CLI entrypoints thin and
 * puts the parsing under phpcs and phpstan, unlike scripts/.
 *
 * Only the mysql: driver is accepted. A DSN naming another driver is a
 * mistake worth failing on rather than silently reinterpreting.
 */
final class DatabaseDsn
{
    private const PREFIX = 'mysql:';
    private const DEFAULT_PORT = 3306;

    private function __construct(
        public readonly string $dsn,
        public readonly string $host,
        public readonly int $port,
        public readonly string $database,
        public readonly string $charset
    ) {
    }

    /**
     * @throws InvalidArgumentException when the DSN is not a usable mysql: DSN
     */
    public static function fromString(string $dsn): self
    {
        $dsn = trim($dsn);

        if (!str_starts_with($dsn, self::PREFIX)) {
            throw new InvalidArgumentException(
                sprintf('Expected a "mysql:" DSN, got "%s".', $dsn)
            );
        }

        $parameters = self::parseParameters(substr($dsn, strlen(self::PREFIX)));

        $host = $parameters['host'] ?? '';
        if ($host === '') {
            throw new InvalidArgumentException(sprintf('DSN "%s" does not name a host.', $dsn));
        }

        $database = $parameters['dbname'] ?? '';
        if ($database === '') {
            throw new InvalidArgumentException(sprintf('DSN "%s" does not name a database.', $dsn));
        }

        $port = self::DEFAULT_PORT;
        if (isset($parameters['port']) && $parameters['port'] !== '') {
            if (!ctype_digit($parameters['port'])) {
                throw new InvalidArgumentException(
                    sprintf('DSN "%s" has a non-numeric port.', $dsn)
                );
            }
            $port = (int) $parameters['port'];
        }

        return new self(
            $dsn,
            $host,
            $port,
            $database,
            $parameters['charset'] ?? 'utf8mb4'
        );
    }

    /**
     * A database whose name ends in _test is safe to destroy in a drill.
     *
     * Everything else is treated as potentially production and needs a second,
     * explicit opt-in before any destructive operation touches it.
     */
    public function isTestDatabase(): bool
    {
        return str_ends_with($this->database, '_test');
    }

    /**
     * The same server, with no database selected.
     *
     * Required for DROP DATABASE / CREATE DATABASE: a connection bound to the
     * database being dropped cannot outlive it.
     */
    public function serverDsn(): string
    {
        return sprintf('mysql:host=%s;port=%d;charset=%s', $this->host, $this->port, $this->charset);
    }

    /**
     * Quotes the database name for use in DDL.
     *
     * Backticks are the MySQL identifier quote, and a literal backtick inside
     * an identifier is escaped by doubling it. The name comes from an operator
     * supplied DSN, so it is never pasted into SQL unquoted.
     */
    public function quotedDatabase(): string
    {
        return '`' . str_replace('`', '``', $this->database) . '`';
    }

    /**
     * @return array<string, string>
     */
    private static function parseParameters(string $body): array
    {
        $parameters = [];

        foreach (explode(';', $body) as $pair) {
            $pair = trim($pair);
            if ($pair === '') {
                continue;
            }

            $separator = strpos($pair, '=');
            if ($separator === false) {
                throw new InvalidArgumentException(
                    sprintf('DSN fragment "%s" is not a key=value pair.', $pair)
                );
            }

            $key = strtolower(trim(substr($pair, 0, $separator)));
            $parameters[$key] = trim(substr($pair, $separator + 1));
        }

        return $parameters;
    }
}
