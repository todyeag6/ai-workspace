<?php

declare(strict_types=1);

namespace App\Tests;

use PDO;
use PHPUnit\Framework\TestCase as Base;
use RuntimeException;

/**
 * Base test case for the platform suite.
 *
 * Every test runs against real MySQL 8 - not SQLite - because FR-TEN-002
 * requires prepared-statement and tenant-scope parity with production.
 *
 * Lifecycle per test:
 *   1. Connect to the test database.
 *   2. Apply all migrations in lexicographic order (FR-DEP-001: ordered).
 *   3. Open a transaction.
 *   4. ... test body ...
 *   5. Roll the transaction back, discarding every write.
 *
 * PITFALL: MySQL DDL causes an implicit commit. Migrations therefore run
 * BEFORE beginTransaction(), and no test may issue DDL inside its body -
 * doing so would commit the surrounding transaction and break isolation.
 * Tests needing a scratch table must create it in setUpBeforeClass().
 */
abstract class TestCase extends Base
{
    protected PDO $pdo;

    /**
     * Tracks whether THIS instance opened the transaction, so tearDown() can
     * tell a genuine rollback from a transaction that was implicitly committed
     * away by a test issuing DDL (CREATE/DROP/ALTER/TRUNCATE) inside its body.
     */
    private bool $transactionOwned = false;

    protected function setUp(): void
    {
        $dsn = getenv('TEST_DB_DSN');
        if ($dsn === false || $dsn === '') {
            throw new RuntimeException('TEST_DB_DSN is not set; cannot reach the test database.');
        }

        $this->pdo = new PDO($dsn, 'root', 'root', [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);

        $this->applyMigrations();

        $this->pdo->beginTransaction();
        $this->transactionOwned = true;
    }

    protected function tearDown(): void
    {
        if (!$this->transactionOwned) {
            return;
        }

        if (isset($this->pdo) && $this->pdo->inTransaction()) {
            $this->pdo->rollBack();
        } else {
            // The transaction is no longer active, but WE opened it: a test
            // issued DDL (implicit commit) and leaked its writes into every
            // subsequent test. Fail loudly instead of silently corrupting state.
            throw new RuntimeException(
                'Transaction was not active in tearDown(): a test issued DDL '
                . '(CREATE/DROP/ALTER/TRUNCATE) inside its body, implicitly '
                . 'committing and breaking rollback isolation. Create scratch '
                . 'tables in setUpBeforeClass(), never inside a test method.'
            );
        }

        $this->transactionOwned = false;
    }

    /**
     * Applies every migrations/*.sql file in deterministic filename order.
     *
     * Runs outside any transaction: MySQL implicitly commits on DDL, so
     * wrapping migrations in a transaction would be a lie.
     */
    private function applyMigrations(): void
    {
        // glob() returns false when the directory is missing, and its ordering
        // is not guaranteed across platforms - normalise both.
        $files = glob(__DIR__ . '/../migrations/*.sql') ?: [];
        sort($files, SORT_STRING);

        foreach ($files as $file) {
            $sql = file_get_contents($file);
            if ($sql === false) {
                throw new RuntimeException(sprintf('Unable to read migration "%s".', $file));
            }

            $statements = array_filter(array_map('trim', explode(';', $sql)));
            foreach ($statements as $statement) {
                $this->pdo->exec($statement);
            }
        }
    }
}
