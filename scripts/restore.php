<?php

declare(strict_types=1);

/**
 * FR-DEP-001 / AC-004: restores a gzipped logical backup into one database.
 *
 *   php scripts/restore.php --dsn='mysql:host=db;dbname=aiwebscapes_test;charset=utf8mb4' \
 *                           --in=/app/backups/aiwebscapes_test-drill.sql.gz
 *
 *   php scripts/restore.php --dsn='...' --in='...' --drop-database --confirm
 *
 * --dsn is MANDATORY and has NO DEFAULT, so the target is always something an
 * operator typed out in full rather than something inherited from a shell.
 *
 * The dump produced by backup.php carries no CREATE DATABASE or USE statement,
 * so the destination is decided here and only here, by --dsn. The database is
 * created if absent, which is what makes a restore-onto-nothing possible.
 *
 * DESTRUCTION GUARDS, in order of severity:
 *   --drop-database   asks for the target to be dropped and recreated first,
 *                     which is the only way to prove a restore really came
 *                     from the dump rather than from leftovers.
 *   --confirm         must accompany --drop-database. Without it the script
 *                     refuses and changes nothing.
 *   --allow-non-test  additionally required when the target database name does
 *                     not end in _test. Dropping aiwebscapes therefore takes
 *                     three deliberate flags, dropping aiwebscapes_test two.
 *
 * mysql is executed through proc_open with an argument ARRAY - no shell, no
 * interpolation - and the dump is decompressed straight into its stdin.
 */

require __DIR__ . '/../vendor/autoload.php';

use App\Infra\CliOptions;
use App\Infra\DatabaseDsn;
use App\Infra\MysqlBinary;

const USAGE = <<<TXT
Usage: php scripts/restore.php --dsn=<pdo-mysql-dsn> --in=<path.sql.gz>
                               [--drop-database --confirm [--allow-non-test]]
                               [--user=<user>] [--password=<password>]
                               [--mysql=<binary>]

  --dsn             REQUIRED. e.g. 'mysql:host=db;dbname=aiwebscapes_test;charset=utf8mb4'
                    There is no default: this script never guesses a target.
  --in              REQUIRED. The .sql.gz produced by scripts/backup.php.
  --drop-database   DESTRUCTIVE. Drop and recreate the target first.
  --confirm         Required alongside --drop-database.
  --allow-non-test  Also required when the database name does not end in _test.
  --user            Defaults to \$DB_USER, then 'root'.
  --password        Defaults to \$DB_PASSWORD, then 'root'.
  --mysql           Binary to run. Defaults to 'mysql'.
TXT;

/**
 * @param  list<string> $argv
 */
function main(array $argv): int
{
    try {
        $options = CliOptions::fromArgv(array_slice($argv, 1));
        $dsn = DatabaseDsn::fromString($options->requireValue('dsn'));
        $in = $options->requireValue('in');
    } catch (Throwable $error) {
        fwrite(STDERR, $error->getMessage() . PHP_EOL . PHP_EOL . USAGE . PHP_EOL);

        return 2;
    }

    $dropDatabase = $options->has('drop-database');

    if ($dropDatabase && !$options->has('confirm')) {
        fwrite(STDERR, sprintf(
            'Refusing to drop database "%s" on %s: --drop-database requires --confirm.'
            . ' Nothing was changed.' . PHP_EOL,
            $dsn->database,
            $dsn->host
        ));

        return 2;
    }

    if ($dropDatabase && !$dsn->isTestDatabase() && !$options->has('allow-non-test')) {
        fwrite(STDERR, sprintf(
            'Refusing to drop database "%s": the name does not end in _test, so it is'
            . ' treated as production. Pass --allow-non-test if you really mean it.'
            . ' Nothing was changed.' . PHP_EOL,
            $dsn->database
        ));

        return 2;
    }

    $user = $options->valueOrEnv('user', 'DB_USER', 'root');
    $password = $options->valueOrEnv('password', 'DB_PASSWORD', 'root');
    $binary = $options->valueOrEnv('mysql', 'MYSQL_BINARY', 'mysql');

    try {
        if (!is_file($in)) {
            throw new RuntimeException(sprintf('Dump "%s" does not exist.', $in));
        }

        // Connected to the server, NOT to the database: a connection bound to
        // the target cannot survive dropping it.
        $server = new PDO($dsn->serverDsn(), $user, $password, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);

        if ($dropDatabase) {
            fwrite(STDERR, sprintf(
                'WARNING: dropping database "%s" on %s:%d as instructed.' . PHP_EOL,
                $dsn->database,
                $dsn->host,
                $dsn->port
            ));
            $server->exec('DROP DATABASE IF EXISTS ' . $dsn->quotedDatabase());
        }

        // Idempotent, and the reason a restore can land on a server where the
        // database no longer exists at all.
        $server->exec(sprintf(
            'CREATE DATABASE IF NOT EXISTS %s CHARACTER SET %s COLLATE utf8mb4_unicode_ci',
            $dsn->quotedDatabase(),
            $dsn->charset
        ));

        $bytes = (new MysqlBinary($binary, $password))->loadFromGzip(
            [
                '--host=' . $dsn->host,
                '--port=' . $dsn->port,
                '--user=' . $user,
                '--default-character-set=' . $dsn->charset,
                '--batch',
                $dsn->database,
            ],
            $in
        );

        fwrite(STDOUT, sprintf(
            'Restored %s -> %s@%s:%d (%d bytes SQL%s)' . PHP_EOL,
            $in,
            $dsn->database,
            $dsn->host,
            $dsn->port,
            $bytes,
            $dropDatabase ? ', database recreated' : ''
        ));

        return 0;
    } catch (Throwable $error) {
        fwrite(STDERR, 'Restore failed: ' . $error->getMessage() . PHP_EOL);

        return 1;
    }
}

exit(main($argv));
