<?php

declare(strict_types=1);

namespace App\Tests\Infra;

use App\Tests\TestCase;
use PDO;
use RuntimeException;

/**
 * AC-004 / FR-DEP-001: proves the backup and restore path actually works.
 *
 * The drill is the whole point: seed N rows, take a backup, destroy the
 * database completely, restore it, and prove the row counts came back
 * identical. A backup script that has never been restored from is not a
 * backup, it is a file.
 *
 * TRANSACTION / ISOLATION DESIGN (deliberate, see the base class contract):
 *
 * App\Tests\TestCase opens a transaction on $this->pdo before every test body
 * and its tearDown() throws if that transaction is no longer active, because
 * that would mean the test issued DDL and implicitly committed. This test
 * therefore NEVER touches $this->pdo. It opens its own short-lived PDO
 * connections in autocommit mode for every step of the drill, so:
 *
 *   - the seeded rows are genuinely COMMITTED, which is the only way
 *     mysqldump - a separate process on a separate connection - can see them
 *   - the base transaction stays open and empty for the whole test, holds no
 *     metadata locks, does not block DROP DATABASE, and is rolled back
 *     normally by the untouched base tearDown()
 *
 * Everything this test commits is cleaned up again on its own connections, so
 * the suite stays repeatable however many times it runs.
 *
 * The drill targets aiwebscapes_test only. It reads TEST_DB_DSN and passes it
 * to the scripts explicitly - the scripts have no default DSN, which is what
 * keeps a stray invocation from ever pointing at the production database.
 */
final class BackupRestoreTest extends TestCase
{
    /** Number of rows seeded before the backup is taken. */
    private const SEED_ROWS = 7;

    /** Marker written into every seeded row so cleanup can find them again. */
    private const MARKER = 'ac004-drill@aiwebscapes.local';

    /** Deterministic name: re-running the drill overwrites rather than piles up. */

    private static function repositoryRoot(): string
    {
        return dirname(__DIR__, 2);
    }

    private static function testDsn(): string
    {
        $dsn = getenv('TEST_DB_DSN');
        if ($dsn === false || $dsn === '') {
            self::fail('TEST_DB_DSN is not set in the environment.');
        }

        return $dsn;
    }

    /**
     * A fresh autocommit connection, independent of the base transaction.
     */
    private static function freshConnection(): PDO
    {
        return new PDO(self::testDsn(), 'root', 'root', [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
    }

    /**
     * A connection that is NOT bound to aiwebscapes_test, so it survives the
     * database being dropped out from under it.
     */
    private static function serverConnection(): PDO
    {
        return new PDO('mysql:host=db;charset=utf8mb4', 'root', 'root', [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
    }

    /**
     * Runs one of the scripts under test in its own PHP process.
     *
     * The command is passed to proc_open as an ARRAY, so no shell is involved
     * and no argument is ever interpolated into a command string.
     *
     * @param  list<string> $arguments
     * @return array{code: int, stdout: string, stderr: string}
     */
    private static function runScript(string $script, array $arguments): array
    {
        $command = array_merge([PHP_BINARY, self::repositoryRoot() . '/scripts/' . $script], $arguments);

        $descriptors = [
            0 => ['file', '/dev/null', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $pipes = [];
        $process = proc_open($command, $descriptors, $pipes, self::repositoryRoot());
        if (!is_resource($process)) {
            throw new RuntimeException(sprintf('Unable to start scripts/%s.', $script));
        }

        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        return [
            'code' => proc_close($process),
            'stdout' => $stdout === false ? '' : $stdout,
            'stderr' => $stderr === false ? '' : $stderr,
        ];
    }

    /**
     * @param array{code: int, stdout: string, stderr: string} $result
     */
    private static function describe(string $script, array $result): string
    {
        return sprintf(
            "%s exited %d\n--- stdout ---\n%s\n--- stderr ---\n%s",
            $script,
            $result['code'],
            $result['stdout'],
            $result['stderr']
        );
    }

    private static function countRows(PDO $connection, string $sql): int
    {
        $statement = $connection->query($sql);
        if ($statement === false) {
            throw new RuntimeException(sprintf('Query failed: %s', $sql));
        }

        return (int) $statement->fetchColumn();
    }

    private static function seedRows(PDO $connection, int $rows): void
    {
        $insert = $connection->prepare(
            'INSERT INTO demo_requests (name, email, automation_need, preferred_contact)'
            . ' VALUES (:name, :email, :need, :contact)'
        );

        for ($i = 1; $i <= $rows; $i++) {
            $insert->execute([
                'name' => sprintf('Drill Row %d', $i),
                'email' => self::MARKER,
                'need' => sprintf('AC-004 backup restore drill row %d', $i),
                'contact' => 'email',
            ]);
        }
    }

    private static function deleteSeededRows(): void
    {
        $connection = self::freshConnection();
        $delete = $connection->prepare('DELETE FROM demo_requests WHERE email = :email');
        $delete->execute(['email' => self::MARKER]);
    }

    /**
     * Re-applies the baseline so the database is never left without its schema
     * if the drill aborts part-way through.
     */
    /**
     * The database this drill is allowed to destroy, read from TEST_DB_DSN.
     *
     * NEVER hardcode 'aiwebscapes_test' in the destructive statements below.
     * The suite supports a per-process database (TEST_DB_DSN override) so that
     * concurrent runs - two reviewer subagents, for instance - do not corrupt
     * each other. A hardcoded name would make an isolated run drop the SHARED
     * database out from under whoever else is using it: the exact cross-process
     * corruption the override exists to prevent.
     */
    private static function drillDatabase(): string
    {
        $dsn = getenv('TEST_DB_DSN');
        if ($dsn === false || $dsn === '') {
            throw new RuntimeException('TEST_DB_DSN is not set; refusing to guess the drill database.');
        }

        if (preg_match('/dbname=([A-Za-z0-9_]+)/', $dsn, $matches) !== 1) {
            throw new RuntimeException(sprintf('TEST_DB_DSN does not name a dbname: %s', $dsn));
        }

        return $matches[1];
    }

    /**
     * Re-applies the baseline so the database is never left without its schema
     * if the drill aborts part-way through.
     */
    /**
     * Dump path, namespaced by the target database so two concurrent runs
     * (each with its own TEST_DB_DSN) cannot overwrite each other's dump
     * mid-drill.
     */
    private static function dumpPath(): string
    {
        return sprintf('/app/backups/%s-drill.sql.gz', self::drillDatabase());
    }

    /**
     * Guarantees the test database exists before we point a DB-scoped
     * connection at it. The drill DROPs aiwebscapes_test mid-run; if a prior
     * aborted drill (or the gap between DROP and CREATE) left it missing, a
     * naive freshConnection() would die with "Unknown database" on the very
     * first statement. Creating it here (idempotent) makes the drill
     * self-healing regardless of what state a previous run left behind.
     */
    private static function ensureDatabase(): void
    {
        self::serverConnection()->exec(
            'CREATE DATABASE IF NOT EXISTS ' . self::drillDatabase()
            . ' CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci'
        );
    }

    /**
     * Re-applies the baseline so the database is never left without its schema
     * if the drill aborts part-way through.
     */
    private static function reapplyBaseline(): void
    {
        self::ensureDatabase();

        $sql = file_get_contents(self::repositoryRoot() . '/migrations/000_baseline.sql');
        if ($sql === false) {
            throw new RuntimeException('Unable to read migrations/000_baseline.sql.');
        }

        $connection = self::freshConnection();
        foreach (array_filter(array_map('trim', explode(';', $sql))) as $statement) {
            $connection->exec($statement);
        }
    }

    /**
     * The AC-004 evidence: N committed rows survive a full destroy-and-restore.
     */
    public function test_backup_then_drop_then_restore_returns_identical_row_counts(): void
    {
        // 0. Clean up any marker rows left by a previous run that aborted
        // before its end-of-test cleanup (this test DROPs and recreates the
        // whole database, so a mid-drill abort leaves committed residue).
        // Doing this FIRST makes the drill idempotent across re-runs.
        // Ensure the database exists before any DB-scoped connection - a
        // prior aborted drill may have left it dropped.
        self::ensureDatabase();
        self::deleteSeededRows();

        // 1. Seed committed rows so a separate mysqldump process can see them.
        $seeded = self::freshConnection();
        self::seedRows($seeded, self::SEED_ROWS);

        $rowsBefore = self::countRows($seeded, 'SELECT COUNT(*) FROM demo_requests');
        $markersBefore = self::countRows(
            $seeded,
            "SELECT COUNT(*) FROM demo_requests WHERE email = '" . self::MARKER . "'"
        );
        self::assertSame(self::SEED_ROWS, $markersBefore, 'Seeding must commit the drill rows.');

        // 2. Back the database up.
        $backup = self::runScript('backup.php', [
            '--dsn=' . self::testDsn(),
            '--out=' . self::dumpPath(),
        ]);
        self::assertSame(0, $backup['code'], self::describe('backup.php', $backup));
        self::assertFileExists(self::dumpPath());

        $dumpSize = filesize(self::dumpPath());
        self::assertIsInt($dumpSize);
        self::assertGreaterThan(0, $dumpSize, 'The dump must not be empty.');

        $magic = file_get_contents(self::dumpPath(), false, null, 0, 2);
        self::assertSame("\x1f\x8b", $magic, 'The dump must be a real gzip stream.');

        // 3. Destroy the database completely, and prove it is really gone.
        $server = self::serverConnection();
        $server->exec('DROP DATABASE IF EXISTS ' . self::drillDatabase());
        $server->exec(
            'CREATE DATABASE ' . self::drillDatabase()
            . ' CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci'
        );

        $tablesAfterDrop = self::countRows(
            $server,
            "SELECT COUNT(*) FROM information_schema.TABLES"
            . " WHERE TABLE_SCHEMA = '" . self::drillDatabase() . "'"
        );
        self::assertSame(0, $tablesAfterDrop, 'The database must be empty before the restore.');

        // 4. Restore from the dump.
        $restore = self::runScript('restore.php', [
            '--dsn=' . self::testDsn(),
            '--in=' . self::dumpPath(),
        ]);
        self::assertSame(0, $restore['code'], self::describe('restore.php', $restore));

        // 5. On a brand new connection, the data must be byte-for-byte back.
        $restored = self::freshConnection();
        self::assertSame(
            $rowsBefore,
            self::countRows($restored, 'SELECT COUNT(*) FROM demo_requests'),
            'The restored row count must equal the backed-up row count.'
        );
        self::assertSame(
            self::SEED_ROWS,
            self::countRows(
                $restored,
                "SELECT COUNT(*) FROM demo_requests WHERE email = '" . self::MARKER . "'"
            ),
            'Every seeded row must come back.'
        );

        $names = $restored->query(
            "SELECT name FROM demo_requests WHERE email = '" . self::MARKER . "' ORDER BY id"
        );
        self::assertNotFalse($names);
        self::assertSame('Drill Row 1', $names->fetchColumn(), 'Restored values must match, not just counts.');

        // The schema came back too, not merely the rows.
        foreach (['demo_requests', 'users', 'schema_migrations'] as $table) {
            self::assertSame(
                1,
                self::countRows(
                    $restored,
                    "SELECT COUNT(*) FROM information_schema.TABLES"
                    . " WHERE TABLE_SCHEMA = '" . self::drillDatabase() . "'"
                    . " AND TABLE_NAME = '" . $table . "'"
                ),
                sprintf('Table %s must exist after the restore.', $table)
            );
        }

        // 6. Leave the database exactly as the suite expects to find it.
        self::deleteSeededRows();
        self::reapplyBaseline();
    }

    /**
     * Guarantees the test database exists and carries the full schema, however
     * the drill above exited.
     *
     * The drill DROPs aiwebscapes_test and depends on a multi-step restore to
     * put it back. Every one of those steps can fail - a transient
     * "1213 Deadlock" against the concurrently-migrating suite is enough - and
     * without this hook an aborted drill leaves the database DESTROYED. Each
     * following test then dies in setUp() with "Unknown database
     * 'aiwebscapes_test'", turning one transient error into a suite-wide
     * cascade that looks like a code regression.
     *
     * Runs after every test in this class regardless of outcome, so the blast
     * radius of a failed drill is the drill itself.
     */
    protected function tearDown(): void
    {
        try {
            // Only guarantee the DATABASE exists - deliberately not the schema.
            // reapplyBaseline() applies 000_baseline.sql alone, so calling it
            // here would leave a PARTIAL schema (no 001 tenant/identity tables)
            // that looks healthy. Recreating the empty database is enough:
            // TestCase::applyMigrations() detects the missing schema via
            // schemaLooksApplied() and replays every migration in order.
            self::serverConnection()->exec(
                'CREATE DATABASE IF NOT EXISTS ' . self::drillDatabase()
                . ' CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci'
            );
        } finally {
            // The base tearDown() owns the transaction-rollback contract and
            // its loud DDL-leak guard - it must run even if the repair above
            // throws.
            parent::tearDown();
        }
    }

    /**
     * Prod safety: restore.php will not drop a database on a bare --dsn.
     */
    public function test_restore_refuses_to_drop_the_database_without_confirmation(): void
    {
        $result = self::runScript('restore.php', [
            '--dsn=' . self::testDsn(),
            '--in=' . self::dumpPath(),
            '--drop-database',
        ]);

        self::assertNotSame(0, $result['code'], self::describe('restore.php', $result));
        self::assertStringContainsString('--confirm', $result['stderr']);

        // The database is untouched: the schema is still there.
        self::assertSame(
            1,
            self::countRows(
                self::freshConnection(),
                "SELECT COUNT(*) FROM information_schema.TABLES"
                . " WHERE TABLE_SCHEMA = '" . self::drillDatabase() . "'"
                . " AND TABLE_NAME = 'demo_requests'"
            ),
            'A refused drop must leave the database intact.'
        );
    }

    /**
     * Prod safety: none of the three scripts has a default DSN, so an operator
     * who forgets the flag gets an error instead of silently hitting whatever
     * database happened to be configured in the environment.
     */
    public function test_every_script_refuses_to_run_without_an_explicit_dsn(): void
    {
        foreach (['migrate.php', 'backup.php', 'restore.php'] as $script) {
            $result = self::runScript($script, []);

            self::assertNotSame(0, $result['code'], self::describe($script, $result));
            self::assertStringContainsString('--dsn', $result['stderr'], $script . ' must name the missing flag.');
        }
    }
}
