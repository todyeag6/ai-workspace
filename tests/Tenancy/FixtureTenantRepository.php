<?php

declare(strict_types=1);

namespace App\Tests\Tenancy;

use App\Data\TenantRepository;

/**
 * Concrete stand-in used to exercise the abstract App\Data\TenantRepository.
 *
 * PLAN DEVIATION (documented, deliberate)
 * ---------------------------------------
 * The P1-T3 test skeletons in the plan instantiate a `LeadRepository` over a
 * `leads` table. That table does not exist yet - it is created by task P1-T10 -
 * and building the lead feature here to satisfy a test would be scope creep
 * that inverts the plan's own sequencing ("build and prove P1-T3/T4 before any
 * feature above them"). The deliverable of P1-T3 is the ABSTRACT base and the
 * tenancy primitives, not any one concrete repository.
 *
 * So the concrete class is a test fixture over a scratch table, and the three
 * named behaviours from the skeletons are preserved verbatim in spirit:
 *   1. the SELECT is forced tenant-scoped,
 *   2. a null/0 tenant is rejected at construction,
 *   3. a cross-tenant row is invisible.
 * Only the class name changed. When P1-T10 lands, LeadRepository extends this
 * same base and inherits all three properties without re-proving them.
 *
 * It lives in its own file because PSR-1 (enforced by the PSR12 phpcs ruleset)
 * forbids more than one class per file - it cannot be inlined into the test.
 *
 * © AI WebScapes 2026
 */
final class FixtureTenantRepository extends TenantRepository
{
    /**
     * Scratch table created in TenantScopeTest::setUpBeforeClass() and dropped
     * in tearDownAfterClass(). It carries no foreign key to `tenants` on
     * purpose: the cross-tenant proof has to insert a row for a tenant that the
     * migrations never seed, and referential integrity is FR-TEN-001's job
     * (already proven by tests/Identity/SchemaTest.php), not FR-TEN-002's.
     */
    public const TABLE = 'p1t3_scope_probe';

    protected function table(): string
    {
        return self::TABLE;
    }

    /**
     * @return list<string>
     */
    protected function columns(): array
    {
        return ['id', 'tenant_id', 'label'];
    }

    /**
     * @return list<array<string, scalar|null>>
     */
    public function all(): array
    {
        return $this->selectScoped();
    }

    public function relabel(string $id, string $label): int
    {
        return $this->updateScoped(['label' => $label], 'id = :id', ['id' => $id]);
    }

    public function remove(string $id): int
    {
        return $this->deleteScoped('id = :id', ['id' => $id]);
    }

    /**
     * Deliberately hostile caller: tries to smuggle its own :tenant binding in
     * alongside the legitimate parameters, which is exactly the escape hatch
     * FR-TEN-002 has to close. The base must refuse rather than let the caller
     * pick the tenant it reads.
     *
     * @return array<string, scalar|null>|null
     */
    public function findPretendingToBeTenant(string $id, int $tenantId): ?array
    {
        $rows = $this->selectScoped('id = :id', ['id' => $id, 'tenant' => $tenantId]);

        return $rows[0] ?? null;
    }

    /**
     * Second hostile caller: tries to move a row it legitimately owns into
     * another tenant. FR-TEN-001 makes the tenant scope immutable, so the base
     * must refuse to put tenant_id in a SET list at all.
     */
    public function reassignTenant(string $id, int $newTenantId): int
    {
        return $this->updateScoped(['tenant_id' => $newTenantId], 'id = :id', ['id' => $id]);
    }
}
