<?php

declare(strict_types=1);

namespace App\Tests;

use PDO;
use RuntimeException;

/**
 * Proves the App\Tests\TestCase harness contract:
 *   1. $this->pdo is a live connection to the *test* database.
 *   2. A transaction is open for the duration of every test body.
 *   3. Writes made in one test are rolled back and never leak into the next.
 *
 * The scratch table is created in setUpBeforeClass() and dropped in
 * tearDownAfterClass(). Both run OUTSIDE the per-test transaction, which
 * honours the MySQL pitfall that DDL triggers an implicit commit: issuing
 * CREATE/DROP inside a test body would silently commit the transaction and
 * destroy the very isolation this test exists to verify.
 */
final class TestCaseIntegrationTest extends TestCase
{
    private const PROBE_TABLE = 'm4_rollback_probe';

    private static function adminConnection(): PDO
    {
        $dsn = getenv('TEST_DB_DSN');
        if ($dsn === false || $dsn === '') {
            self::fail('TEST_DB_DSN is not set in the environment.');
        }

        return new PDO($dsn, 'root', 'root', [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
    }

    public static function setUpBeforeClass(): void
    {
        // DDL outside the transaction lifecycle - see class docblock. Also
        // re-ensured per test via scratchTableDdl(): the AC-004 drill in
        // tests/Infra/BackupRestoreTest.php DROPs the database mid-suite, and
        // a class-level hook has already run by then.
        self::adminConnection()->exec(self::probeTableDdl());
    }

    /**
     * @return list<string>
     */
    protected function scratchTableDdl(): array
    {
        return [self::probeTableDdl()];
    }

    private static function probeTableDdl(): string
    {
        return 'CREATE TABLE IF NOT EXISTS ' . self::PROBE_TABLE . ' (id INT PRIMARY KEY)';
    }

    public static function tearDownAfterClass(): void
    {
        self::adminConnection()->exec('DROP TABLE IF EXISTS ' . self::PROBE_TABLE);
    }

    /**
     * Runs a single-value query and returns its first column.
     *
     * $this->pdo is built with ERRMODE_EXCEPTION, so query() throws rather
     * than returning false; the explicit false check exists to satisfy static
     * analysis and to fail loudly should that attribute ever be relaxed. It is
     * deliberately a thrown exception and NOT an assertion, so it neither
     * inflates the suite's assertion count nor participates in the
     * rollback-isolation proof below.
     */
    private function queryScalar(string $sql): mixed
    {
        $statement = $this->pdo->query($sql);
        if ($statement === false) {
            throw new RuntimeException(sprintf('Query failed: %s', $sql));
        }

        return $statement->fetchColumn();
    }

    private function probeRowCount(): int
    {
        return (int) $this->queryScalar('SELECT COUNT(*) FROM ' . self::PROBE_TABLE);
    }

    public function test_pdo_is_connected_to_the_test_database(): void
    {
        $database = $this->queryScalar('SELECT DATABASE()');

        // Read the expected name from the DSN rather than hardcoding it, so the
        // suite can run against a per-process database (TEST_DB_DSN override)
        // without this assertion failing. Concurrent runs against ONE shared
        // database corrupt each other - tests/Infra/BackupRestoreTest.php drops
        // it mid-suite - so per-process databases are a supported mode.
        $dsn = getenv('TEST_DB_DSN');
        self::assertIsString($dsn, 'TEST_DB_DSN must be set.');
        self::assertSame(1, preg_match('/dbname=([^;]+)/', $dsn, $matches), 'TEST_DB_DSN must name a dbname.');

        self::assertSame($matches[1], $database);
    }

    public function test_a_transaction_is_active_inside_the_test_body(): void
    {
        self::assertTrue(
            $this->pdo->inTransaction(),
            'The base TestCase must open a transaction before the test body runs.'
        );
    }

    /**
     * Deliberately paired with the sibling method below. Each asserts an empty
     * table on entry, then writes a row under a distinct primary key. Whichever
     * order PHPUnit picks, the second one to execute can only observe an empty
     * table if the first one's INSERT was genuinely rolled back.
     */
    public function test_rollback_isolation_probe_a(): void
    {
        self::assertSame(0, $this->probeRowCount(), 'Probe table must be empty on entry.');

        $this->pdo->exec('INSERT INTO ' . self::PROBE_TABLE . ' (id) VALUES (101)');

        self::assertSame(1, $this->probeRowCount(), 'Write must be visible within its own test.');
    }

    public function test_rollback_isolation_probe_b(): void
    {
        self::assertSame(0, $this->probeRowCount(), 'Probe table must be empty on entry.');

        $this->pdo->exec('INSERT INTO ' . self::PROBE_TABLE . ' (id) VALUES (202)');

        self::assertSame(1, $this->probeRowCount(), 'Write must be visible within its own test.');
    }
}
