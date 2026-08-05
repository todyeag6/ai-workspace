<?php declare(strict_types=1);

namespace App\Tests;

use PDO;

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
        // DDL outside the transaction lifecycle - see class docblock.
        self::adminConnection()->exec(
            'CREATE TABLE IF NOT EXISTS ' . self::PROBE_TABLE . ' (id INT PRIMARY KEY)'
        );
    }

    public static function tearDownAfterClass(): void
    {
        self::adminConnection()->exec('DROP TABLE IF EXISTS ' . self::PROBE_TABLE);
    }

    private function probeRowCount(): int
    {
        return (int) $this->pdo
            ->query('SELECT COUNT(*) FROM ' . self::PROBE_TABLE)
            ->fetchColumn();
    }

    public function test_pdo_is_connected_to_the_test_database(): void
    {
        $database = $this->pdo->query('SELECT DATABASE()')->fetchColumn();

        self::assertSame('aiwebscapes_test', $database);
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
