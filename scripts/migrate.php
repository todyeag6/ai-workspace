<?php

declare(strict_types=1);

/**
 * FR-DEP-001: applies migrations/*.sql in order and records them.
 *
 *   php scripts/migrate.php --dsn='mysql:host=db;dbname=aiwebscapes_test;charset=utf8mb4'
 *   php scripts/migrate.php --dsn='...' --force
 *
 * --dsn is MANDATORY and has NO DEFAULT. Reading DB_DSN from the environment
 * would mean that running this in the wrong shell silently migrates
 * production, so the flag has to be typed out every time.
 *
 * Migrations are applied in lexicographic filename order (000_, 001_, ...)
 * and each filename is recorded in schema_migrations, so a second run is a
 * no-op. --force re-applies everything regardless of what is recorded, which
 * is how the idempotency of the SQL itself gets proven: every statement in
 * every migration must be re-entrant, because tests/TestCase.php re-applies
 * all of them before every single test without consulting this ledger.
 */

require __DIR__ . '/../vendor/autoload.php';

use App\Infra\CliOptions;

const USAGE = <<<TXT
Usage: php scripts/migrate.php --dsn=<pdo-mysql-dsn> [--force]
                               [--user=<user>] [--password=<password>]

  --dsn       REQUIRED. e.g. 'mysql:host=db;dbname=aiwebscapes_test;charset=utf8mb4'
              There is no default: this script never guesses which database
              to migrate.
  --force     Re-apply every migration even if schema_migrations already
              records it. Safe by construction - all migrations are idempotent.
  --user      Defaults to \$DB_USER, then 'root'.
  --password  Defaults to \$DB_PASSWORD, then 'root'.
TXT;

/**
 * Splits a migration file into statements.
 *
 * LIMITATION: this is a naive split on the semicolon character, matching
 * tests/TestCase.php exactly so that both paths agree on what a statement is.
 * It will mis-parse a semicolon inside a string literal or a DELIMITER block,
 * so migrations must not contain either. When P1-T13 introduces triggers this
 * has to be replaced with a real parser - in both places.
 *
 * @return list<string>
 */
function statementsIn(string $sql): array
{
    return array_values(array_filter(array_map('trim', explode(';', $sql))));
}

/**
 * @param  list<string> $argv
 */
function main(array $argv): int
{
    try {
        $options = CliOptions::fromArgv(array_slice($argv, 1));
        $dsn = $options->requireValue('dsn');
    } catch (Throwable $error) {
        fwrite(STDERR, $error->getMessage() . PHP_EOL . PHP_EOL . USAGE . PHP_EOL);

        return 2;
    }

    $user = $options->valueOrEnv('user', 'DB_USER', 'root');
    $password = $options->valueOrEnv('password', 'DB_PASSWORD', 'root');
    $force = $options->has('force');

    try {
        $pdo = new PDO($dsn, $user, $password, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);

        // Bootstrapped here as well as in 000_baseline.sql: the ledger has to
        // exist before the first migration can be recorded in it. IF NOT
        // EXISTS makes the duplication harmless.
        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS schema_migrations ('
            . ' version VARCHAR(255) NOT NULL PRIMARY KEY,'
            . ' applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP'
            . ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
        );

        $recorded = $pdo->query('SELECT version FROM schema_migrations');
        if ($recorded === false) {
            throw new RuntimeException('Unable to read schema_migrations.');
        }
        /** @var list<string> $applied */
        $applied = $recorded->fetchAll(PDO::FETCH_COLUMN);

        $files = glob(__DIR__ . '/../migrations/*.sql') ?: [];
        sort($files, SORT_STRING);

        if ($files === []) {
            fwrite(STDOUT, 'No migrations found in migrations/.' . PHP_EOL);

            return 0;
        }

        $record = $pdo->prepare('INSERT IGNORE INTO schema_migrations (version) VALUES (:version)');
        $appliedCount = 0;
        $skippedCount = 0;

        foreach ($files as $file) {
            $version = basename($file);

            if (in_array($version, $applied, true) && !$force) {
                fwrite(STDOUT, sprintf('  skip     %s (already applied)', $version) . PHP_EOL);
                $skippedCount++;
                continue;
            }

            $sql = file_get_contents($file);
            if ($sql === false) {
                throw new RuntimeException(sprintf('Unable to read migration "%s".', $version));
            }

            $statements = statementsIn($sql);
            foreach ($statements as $statement) {
                $pdo->exec($statement);
            }

            // Recorded only after every statement succeeded, and INSERT IGNORE
            // so that a --force re-apply does not collide with the existing row.
            $record->execute(['version' => $version]);

            fwrite(STDOUT, sprintf(
                '  %s  %s (%d statement%s)',
                $force && in_array($version, $applied, true) ? 're-apply' : 'apply   ',
                $version,
                count($statements),
                count($statements) === 1 ? '' : 's'
            ) . PHP_EOL);
            $appliedCount++;
        }

        fwrite(STDOUT, sprintf(
            'Done: %d applied, %d skipped, %d total.',
            $appliedCount,
            $skippedCount,
            count($files)
        ) . PHP_EOL);

        return 0;
    } catch (Throwable $error) {
        fwrite(STDERR, 'Migration failed: ' . $error->getMessage() . PHP_EOL);

        return 1;
    }
}

exit(main($argv));
