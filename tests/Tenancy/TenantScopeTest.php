<?php

declare(strict_types=1);

namespace App\Tests\Tenancy;

use App\Tenancy\TenantScope;
use App\Tenancy\UnscopedQueryException;
use App\Tests\TestCase;
use PDO;

/**
 * FR-TEN-002 / AC-001: proves that reaching client data without a tenant scope
 * is not merely discouraged but structurally impossible.
 *
 * The three behaviours the plan names for P1-T3:
 *   1. the generated SELECT always carries `tenant_id = :tenant`,
 *   2. a null (or 0, or negative) tenant is rejected at CONSTRUCTION - the
 *      object cannot exist in an unscoped state, so there is no later moment
 *      at which someone forgets to scope,
 *   3. a row belonging to another tenant is invisible: not filtered in the
 *      application layer, but never returned by the database at all.
 *
 * NON-VACUOUSNESS: `test_cross_tenant_row_invisible` asserting null would also
 * pass if the row simply were not there, which would prove nothing. It is
 * therefore paired with `test_own_tenant_row_is_visible`, which reads the SAME
 * seeded row through the SAME repository class under tenant 1 and requires it
 * to come back. The pair only both pass when the WHERE clause is doing real
 * work. Deleting the tenant predicate makes the cross-tenant test fail;
 * deleting the row makes the visibility test fail.
 *
 * On the fixture repository standing in for the plan's LeadRepository, see the
 * class docblock of FixtureTenantRepository.
 *
 * DDL LIFECYCLE: the scratch table is created in setUpBeforeClass() and dropped
 * in tearDownAfterClass(), both outside the per-test transaction. MySQL commits
 * implicitly on DDL, so a CREATE inside a test body would silently end the
 * surrounding transaction and trip the base harness's loud DDL-leak guard.
 *
 * © AI WebScapes 2026
 */
final class TenantScopeTest extends TestCase
{
    private const PROBE_TABLE = FixtureTenantRepository::TABLE;

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
        // re-ensured per test via scratchTableDdl(), because the AC-004 drill
        // in tests/Infra/BackupRestoreTest.php can DROP the database after
        // this class-level hook has already run.
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
        return 'CREATE TABLE IF NOT EXISTS ' . self::PROBE_TABLE . ' ('
            . ' id VARCHAR(64) NOT NULL PRIMARY KEY,'
            . ' tenant_id BIGINT UNSIGNED NOT NULL,'
            . ' label VARCHAR(120) NOT NULL,'
            . ' KEY idx_p1t3_scope_probe_tenant (tenant_id)'
            . ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci';
    }

    public static function tearDownAfterClass(): void
    {
        self::adminConnection()->exec('DROP TABLE IF EXISTS ' . self::PROBE_TABLE);
    }

    /**
     * Seeds one probe row through raw PDO on purpose.
     *
     * The seeder must be able to write rows for tenants the repository under
     * test is NOT scoped to - that is the whole point of the cross-tenant
     * proof - so it cannot itself go through a TenantRepository. Writes land
     * inside the per-test transaction and are rolled back with it.
     */
    private function seedProbe(int $tenant, string $id, string $label = 'seeded'): void
    {
        $statement = $this->pdo->prepare(
            'INSERT INTO ' . self::PROBE_TABLE . ' (id, tenant_id, label)'
            . ' VALUES (:id, :tenant_id, :label)'
        );
        $statement->execute(['id' => $id, 'tenant_id' => $tenant, 'label' => $label]);
    }

    private function countRows(): int
    {
        $statement = $this->pdo->query('SELECT COUNT(*) FROM ' . self::PROBE_TABLE);
        if ($statement === false) {
            self::fail('Probe count query failed.');
        }

        return (int) $statement->fetchColumn();
    }

    private function labelOf(string $id): ?string
    {
        $statement = $this->pdo->prepare(
            'SELECT label FROM ' . self::PROBE_TABLE . ' WHERE id = :id'
        );
        $statement->execute(['id' => $id]);
        $label = $statement->fetchColumn();

        return $label === false ? null : (string) $label;
    }

    // ------------------------------------------------------------------
    // The TenantScope primitive itself
    // ------------------------------------------------------------------

    public function test_scope_rejects_null_tenant(): void
    {
        $this->expectException(UnscopedQueryException::class);

        new TenantScope(null);
    }

    public function test_scope_rejects_zero_tenant(): void
    {
        // 0 is the dangerous one: it is falsy, it survives an (int) cast of an
        // absent value, and in a naive `WHERE tenant_id = 0` it silently
        // matches nothing rather than failing loudly.
        $this->expectException(UnscopedQueryException::class);

        new TenantScope(0);
    }

    public function test_scope_rejects_negative_tenant(): void
    {
        $this->expectException(UnscopedQueryException::class);

        new TenantScope(-1);
    }

    public function test_scope_predicate_binds_the_tenant_column_to_a_placeholder(): void
    {
        $scope = new TenantScope(7);

        self::assertSame(7, $scope->id());
        self::assertSame('tenant_id = :tenant', $scope->predicate());
    }

    public function test_scope_where_clause_ands_the_caller_predicate_after_the_tenant(): void
    {
        $scope = new TenantScope(7);

        // The caller fragment is parenthesised so that an OR inside it cannot
        // widen the result set past the tenant boundary.
        self::assertSame(' WHERE tenant_id = :tenant', $scope->where());
        self::assertSame(' WHERE tenant_id = :tenant AND (id = :id)', $scope->where('id = :id'));
    }

    // ------------------------------------------------------------------
    // Plan skeleton 1: the SELECT is forced tenant-scoped
    // ------------------------------------------------------------------

    public function test_select_is_forced_tenant_scoped(): void
    {
        $repo = new FixtureTenantRepository($this->pdo, tenantId: 1);

        self::assertStringContainsString('tenant_id = :tenant', $repo->listSql());
    }

    // ------------------------------------------------------------------
    // Plan skeleton 2: a null / 0 tenant is rejected at construction
    // ------------------------------------------------------------------

    public function test_null_tenant_rejected_at_construction(): void
    {
        $this->expectException(UnscopedQueryException::class);

        new FixtureTenantRepository($this->pdo, tenantId: null);
    }

    public function test_zero_tenant_rejected_at_construction(): void
    {
        $this->expectException(UnscopedQueryException::class);

        new FixtureTenantRepository($this->pdo, tenantId: 0);
    }

    // ------------------------------------------------------------------
    // Plan skeleton 3 + AC-001: a cross-tenant row is invisible
    // ------------------------------------------------------------------

    public function test_cross_tenant_row_invisible(): void
    {
        $this->seedProbe(tenant: 1, id: 'probe-1');

        self::assertNull(
            (new FixtureTenantRepository($this->pdo, tenantId: 2))->find('probe-1'),
            'AC-001: tenant 2 must not be able to read a row owned by tenant 1.'
        );
    }

    public function test_own_tenant_row_is_visible(): void
    {
        // Non-vacuousness guard for the test above: same row, same repository
        // class, correct tenant. If this passes and the cross-tenant read
        // returns null, the scope predicate is provably the reason.
        $this->seedProbe(tenant: 1, id: 'probe-1', label: 'owned');

        $row = (new FixtureTenantRepository($this->pdo, tenantId: 1))->find('probe-1');
        if ($row === null) {
            self::fail('The owning tenant must still be able to read its own row.');
        }

        self::assertSame('owned', $row['label']);
    }

    public function test_list_returns_only_rows_inside_the_scope(): void
    {
        $this->seedProbe(tenant: 1, id: 'probe-1', label: 'mine');
        $this->seedProbe(tenant: 2, id: 'probe-2', label: 'theirs');

        $rows = (new FixtureTenantRepository($this->pdo, tenantId: 1))->all();

        self::assertCount(1, $rows);
        self::assertSame('mine', $rows[0]['label']);
    }

    // ------------------------------------------------------------------
    // Scoping applies to writes too, not just reads
    // ------------------------------------------------------------------

    public function test_cross_tenant_update_changes_nothing(): void
    {
        $this->seedProbe(tenant: 1, id: 'probe-1', label: 'original');

        $affected = (new FixtureTenantRepository($this->pdo, tenantId: 2))
            ->relabel('probe-1', 'hijacked');

        self::assertSame(0, $affected);
        self::assertSame('original', $this->labelOf('probe-1'));
    }

    public function test_cross_tenant_delete_removes_nothing(): void
    {
        $this->seedProbe(tenant: 1, id: 'probe-1');

        $affected = (new FixtureTenantRepository($this->pdo, tenantId: 2))->remove('probe-1');

        self::assertSame(0, $affected);
        self::assertSame(1, $this->countRows());
    }

    public function test_in_scope_update_does_change_the_row(): void
    {
        // Non-vacuousness guard for the update test above.
        $this->seedProbe(tenant: 1, id: 'probe-1', label: 'original');

        $affected = (new FixtureTenantRepository($this->pdo, tenantId: 1))
            ->relabel('probe-1', 'renamed');

        self::assertSame(1, $affected);
        self::assertSame('renamed', $this->labelOf('probe-1'));
    }

    // ------------------------------------------------------------------
    // The binding cannot be taken away from the repository
    // ------------------------------------------------------------------

    public function test_caller_cannot_override_the_bound_tenant(): void
    {
        $this->seedProbe(tenant: 1, id: 'probe-1');

        // FR-TEN-002: :tenant is bound internally. A caller passing its own
        // value for it must be refused outright - quietly ignoring the
        // parameter would leave callers believing an override happened.
        $this->expectException(UnscopedQueryException::class);

        (new FixtureTenantRepository($this->pdo, tenantId: 2))
            ->findPretendingToBeTenant('probe-1', 1);
    }

    public function test_tenant_id_cannot_be_reassigned_by_an_update(): void
    {
        $this->seedProbe(tenant: 1, id: 'probe-1');

        // FR-TEN-001: the tenant scope is immutable. Allowing tenant_id into a
        // SET list would let an in-scope owner hand its own row to another
        // tenant, which defeats AC-001 from the inside rather than the outside.
        $this->expectException(UnscopedQueryException::class);

        (new FixtureTenantRepository($this->pdo, tenantId: 1))->reassignTenant('probe-1', 2);
    }
}
