<?php

declare(strict_types=1);

namespace App\Tests\ManagedOps;

use App\Data\TenantRepository;
use App\ManagedOps\AgentOwnership;
use App\ManagedOps\AgentOwnershipRepository;
use App\ManagedOps\SlaRecord;
use App\ManagedOps\SlaRepository;
use App\Tests\TestCase;
use PDO;

/**
 * P2-T4 managed-ops repositories on real MySQL (FR-TEN-002 / AC-001 parity).
 *
 * The regression value: (a) ownership is APPEND-ONLY - reassigning writes a
 * new row, the history is intact; (b) tenant scoping holds - a row written in
 * tenant A is invisible from a tenant B repository; (c) breach detection
 * survives a round-trip through the ledger (the breach flag stored equals the
 * SlaRecord's computation); (d) breaches() returns only breached rows.
 *
 * Every write is rolled back by the base TestCase, so this class is safe to
 * run alongside the rest of the suite on a shared-but-per-test-rolled-back DB.
 *
 * © AI WebScapes 2026
 */
final class ManagedOpsRepositoryTest extends TestCase
{
    private const TENANT_A = 11;
    private const TENANT_B = 22;

    private function ownershipRepo(int $tenant): AgentOwnershipRepository
    {
        return new AgentOwnershipRepository($this->pdo, $tenant);
    }

    private function slaRepo(int $tenant): SlaRepository
    {
        return new SlaRepository($this->pdo, $tenant);
    }

    /**
     * @return array<string, string>
     */
    private function roster(): array
    {
        return array_fill_keys(AgentOwnership::roleNames(), 'owner');
    }

    public function test_ownership_is_append_only(): void
    {
        $repo = $this->ownershipRepo(self::TENANT_A);
        $id1 = $repo->assign(new AgentOwnership(1, 1, $this->roster(), 'b1', 'alice'));
        $id2 = $repo->assign(new AgentOwnership(1, 1, $this->roster(), 'b2', 'bob'));

        self::assertGreaterThan(0, $id1);
        self::assertGreaterThan($id1, $id2);

        // The history is intact: both rows exist, latest is current.
        self::assertCount(2, $repo->forAgent(1));
        $current = $repo->current(1);
        self::assertNotNull($current);
        self::assertSame('b2', $current['support_boundary']);
    }

    public function test_tenant_scope_isolates_ownership(): void
    {
        $a = $this->ownershipRepo(self::TENANT_A);
        $b = $this->ownershipRepo(self::TENANT_B);

        $a->assign(new AgentOwnership(1, 1, $this->roster(), 'only-a', 'alice'));

        // Tenant B sees nothing for the same agent id - AC-001.
        self::assertSame([], $b->forAgent(1));
        self::assertNull($b->current(1));
        self::assertCount(1, $a->forAgent(1));
    }

    public function test_sla_breach_round_trips_and_query_filters(): void
    {
        $repo = $this->slaRepo(self::TENANT_A);

        $breach = new SlaRecord('patch', 24.0, 30.0);   // breached
        $pass = new SlaRecord('patch', 24.0, 12.0);     // within
        $breachId = $repo->record(1, $breach);
        $repo->record(1, $pass);

        self::assertSame(1, $repo->forAgent(1)[0]['breached'] ?? null);

        $breaches = $repo->breaches(1);
        self::assertCount(1, $breaches);
        self::assertSame((string) $breachId, (string) $breaches[0]['id']);
    }

    public function test_sla_tenant_scope_isolates(): void
    {
        $a = $this->slaRepo(self::TENANT_A);
        $b = $this->slaRepo(self::TENANT_B);

        $a->record(1, new SlaRecord('incident_response', 4.0, 9.0));

        self::assertSame([], $b->forAgent(1));
        self::assertSame([], $b->breaches(1));
        self::assertCount(1, $a->forAgent(1));
    }

    public function test_repository_construction_throws_without_tenant(): void
    {
        $this->expectException(\App\Tenancy\UnscopedQueryException::class);
        new AgentOwnershipRepository($this->pdo, null);
        // Reference the base so static analysis sees the import is real.
        self::assertInstanceOf(TenantRepository::class, $this->ownershipRepo(self::TENANT_A));
    }
}
