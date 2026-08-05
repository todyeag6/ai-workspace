<?php

declare(strict_types=1);

/**
 * FR-DEP-001 / AC-004: takes a gzipped logical backup of one database.
 *
 *   php scripts/backup.php --dsn='mysql:host=db;dbname=aiwebscapes_test;charset=utf8mb4' \
 *                          --out=/app/backups/aiwebscapes_test-$(date +%s).sql.gz
 *
 * --dsn is MANDATORY and has NO DEFAULT. That single rule is what stops this
 * script from ever reaching for production on its own initiative.
 *
 * mysqldump is executed through proc_open with an argument ARRAY, so no shell
 * is involved and nothing is interpolated into a command string. The password
 * travels in the child's MYSQL_PWD environment variable, never on the command
 * line where ps would expose it. See App\Infra\MysqlBinary.
 *
 * The dump deliberately does NOT use --databases, so it contains no CREATE
 * DATABASE or USE statement. The destination is therefore decided solely by
 * the --dsn given to restore.php, and a dump can never smuggle a target
 * database name of its own.
 */

require __DIR__ . '/../vendor/autoload.php';

use App\Infra\CliOptions;
use App\Infra\DatabaseDsn;
use App\Infra\MysqlBinary;

const USAGE = <<<TXT
Usage: php scripts/backup.php --dsn=<pdo-mysql-dsn> --out=<path.sql.gz>
                              [--user=<user>] [--password=<password>]
                              [--mysqldump=<binary>]

  --dsn        REQUIRED. e.g. 'mysql:host=db;dbname=aiwebscapes_test;charset=utf8mb4'
               There is no default: this script never guesses what to back up.
  --out        REQUIRED. Destination .sql.gz. Parent directories are created.
  --user       Defaults to \$DB_USER, then 'root'.
  --password   Defaults to \$DB_PASSWORD, then 'root'.
  --mysqldump  Binary to run. Defaults to 'mysqldump'.
TXT;

/**
 * @param  list<string> $argv
 */
function main(array $argv): int
{
    try {
        $options = CliOptions::fromArgv(array_slice($argv, 1));
        $dsn = DatabaseDsn::fromString($options->requireValue('dsn'));
        $out = $options->requireValue('out');
    } catch (Throwable $error) {
        fwrite(STDERR, $error->getMessage() . PHP_EOL . PHP_EOL . USAGE . PHP_EOL);

        return 2;
    }

    $user = $options->valueOrEnv('user', 'DB_USER', 'root');
    $password = $options->valueOrEnv('password', 'DB_PASSWORD', 'root');
    $binary = $options->valueOrEnv('mysqldump', 'MYSQLDUMP_BINARY', 'mysqldump');

    try {
        // --single-transaction gives a consistent snapshot of the InnoDB
        // tables without locking writers out. --quick streams row by row
        // instead of buffering whole tables in the client.
        $bytes = (new MysqlBinary($binary, $password))->dumpToGzip(
            [
                '--host=' . $dsn->host,
                '--port=' . $dsn->port,
                '--user=' . $user,
                '--default-character-set=' . $dsn->charset,
                '--single-transaction',
                '--quick',
                '--routines',
                '--skip-dump-date',
                $dsn->database,
            ],
            $out
        );

        $compressed = filesize($out);

        fwrite(STDOUT, sprintf(
            'Backed up %s@%s:%d -> %s (%d bytes SQL, %s bytes gzip)' . PHP_EOL,
            $dsn->database,
            $dsn->host,
            $dsn->port,
            $out,
            $bytes,
            $compressed === false ? 'unknown' : (string) $compressed
        ));

        return 0;
    } catch (Throwable $error) {
        fwrite(STDERR, 'Backup failed: ' . $error->getMessage() . PHP_EOL);

        return 1;
    }
}

exit(main($argv));
