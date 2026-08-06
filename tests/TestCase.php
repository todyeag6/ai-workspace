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
 *   2. Ensure all migrations have been applied in lexicographic order
 *      (FR-DEP-001: ordered) - ONCE PER PROCESS, see applyMigrations().
 *   3. Open a transaction.
 *   4. ... test body ...
 *   5. Roll the transaction back, discarding every write.
 *
 * PITFALL: MySQL DDL causes an implicit commit. Migrations therefore run
 * BEFORE beginTransaction(), and no test may issue DDL inside its body -
 * doing so would commit the surrounding transaction and break isolation.
 * Tests needing a scratch table must override scratchTableDdl() (see below),
 * NOT setUpBeforeClass(). A class-level hook runs once and is silently defeated
 * by tests/Infra/BackupRestoreTest.php dropping the whole database mid-suite;
 * per-test re-ensurance is what actually survives that.
 *
 * Isolation is unchanged by the once-per-process migration: the schema is
 * shared, but every test's DATA writes still live and die inside its own
 * transaction.
 */
abstract class TestCase extends Base
{
    protected PDO $pdo;

    /**
     * Whether migrations have already been applied in THIS PHP process.
     *
     * Static (process-scoped) rather than per-instance: PHPUnit runs the whole
     * suite in a single process by default, so one pass covers every test.
     */
    private static bool $migrationsApplied = false;

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

        // Must stay HERE, before beginTransaction(): migrations are DDL, and
        // DDL implicitly commits on MySQL. A no-op after the first test.
        $this->applyMigrations();

        // Also before beginTransaction(), and for the same reason: a subclass
        // declaring scratch DDL gets it re-ensured per test, so the AC-004
        // drill dropping the database cannot leave it missing. See
        // scratchTableDdl().
        foreach ($this->scratchTableDdl() as $ddl) {
            $this->assertScratchDdl($ddl);
            $this->pdo->exec($ddl);
        }

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
                . 'tables by overriding scratchTableDdl(), never inside a test method body.'
            );
        }

        $this->transactionOwned = false;
    }

    /**
     * Applies every migrations/*.sql file in deterministic filename order.
     *
     * Runs outside any transaction: MySQL implicitly commits on DDL, so
     * wrapping migrations in a transaction would be a lie.
     *
     * ONCE PER PROCESS, not once per test. Re-applying in every setUp() costs
     * O(tests x statements): the schema grows but the work per test does not
     * shrink, so the suite slows down quadratically as both counts rise. The
     * per-test isolation guarantee does not depend on it - that comes purely
     * from beginTransaction()/rollBack(), which remain per-test.
     *
     * Migrations MUST still be idempotent: a fresh process re-applies them
     * against a database that very likely already carries the schema (the test
     * database is not dropped between runs). CREATE TABLE IF NOT EXISTS,
     * guarded ALTERs, INSERT IGNORE - the contract is unchanged.
     */
    private function applyMigrations(): void
    {
        if (self::$migrationsApplied && $this->schemaLooksApplied()) {
            return;
        }

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

        // Set only after a clean pass: if a migration throws, the next test
        // retries rather than silently running against a half-built schema.
        self::$migrationsApplied = true;
    }

    /**
     * Idempotent `CREATE TABLE IF NOT EXISTS` statements for scratch tables
     * this test class needs. Override in a subclass; default is none.
     *
     * WHY THIS IS PER-TEST AND NOT setUpBeforeClass(): a class-level hook runs
     * ONCE, but tests/Infra/BackupRestoreTest.php runs the AC-004 drill and
     * DROPs the whole database mid-suite. Any class ordered after it whose
     * scratch table was created in setUpBeforeClass() then fails with
     * "Table ... doesn't exist" - intermittently, because it depends purely on
     * test ordering. Re-ensuring the DDL before every test is a couple of
     * cheap no-op statements and makes the class order-independent.
     *
     * Runs BEFORE beginTransaction() for the usual reason: MySQL implicitly
     * commits on DDL, so issuing it inside the test transaction would silently
     * break rollback isolation and trip the DDL-leak guard in tearDown().
     *
     * @return list<string>
     */
    protected function scratchTableDdl(): array
    {
        return [];
    }

    /**
     * The hook contract is "idempotent CREATE TABLE IF NOT EXISTS only". Without
     * this guard a subclass returning an INSERT/DROP would leak data across
     * every test permanently, and tearDown() structurally CANNOT catch it
     * because no transaction is open yet at that point. Enforce the contract.
     */
    private function assertScratchDdl(string $ddl): void
    {
        $normalised = strtoupper(ltrim($ddl));
        if (!str_starts_with($normalised, 'CREATE TABLE IF NOT EXISTS')) {
            throw new RuntimeException(sprintf(
                'scratchTableDdl() must return only idempotent "CREATE TABLE IF NOT EXISTS" '
                . 'statements; got: %s',
                $ddl
            ));
        }
    }

    /**
     * Cheap confirmation that the live database still carries the migrated
     * schema, guarding the once-per-process fast path above.
     *
     * WHY THE FLAG ALONE IS NOT ENOUGH: a process-scoped boolean asserts "this
     * process already migrated", which is a claim about the PROCESS, not the
     * DATABASE. tests/Infra/BackupRestoreTest.php runs the AC-004 drill and
     * DROPs aiwebscapes_test mid-suite; if that drill aborts before restoring,
     * the schema is gone while the flag still reads true, and every later test
     * dies with "Unknown database" or "table ... doesn't exist".
     *
     * Deliberately ONE indexed information_schema count rather than a full
     * verification: this runs before every test, so it must stay far cheaper
     * than the migration pass it protects (~62 statements and climbing). It
     * only has to catch the catastrophic case - the schema vanishing wholesale
     * - not subtle drift, which the idempotent migrations repair anyway.
     */
    private function schemaLooksApplied(): bool
    {
        $expected = count(glob(__DIR__ . '/../migrations/*.sql') ?: []);
        if ($expected === 0) {
            return true;
        }

        $statement = $this->pdo->query(
            'SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()'
        );
        if ($statement === false) {
            return false;
        }

        // The baseline alone creates several tables, so a healthy migrated
        // schema always has at least as many tables as migration files. A
        // dropped and freshly recreated database reports 0 and forces a
        // re-apply.
        return (int) $statement->fetchColumn() >= $expected;
    }
}
