<?php

declare(strict_types=1);

namespace App\Tests\Dashboard;

use App\Dashboard\DashboardController;
use App\Dashboard\DashboardRepository;
use App\Dashboard\DashboardView;
use App\Tests\TestCase;
use PDO;

/**
 * P1-T15 pipeline + exceptions-queue behaviour (FR-DASH-001/002,
 * LFR-DASH-001/002/003, LBR-5.8).
 *
 * DB-backed: seeds tenant 1 with leads, pending AI analyses and failed
 * deliveries, then asserts the dashboard's read-model reflects exactly that
 * tenant's data (AC-001 - no cross-tenant leak).
 */
final class PipelineTest extends TestCase
{
    /**
     * LFR-DASH-001 - the pipeline state list, in canonical order.
     *
     * The platform's lead lifecycle is the FIVE states that actually exist in
     * migrations/005_leads.sql. This pins that contract.
     */
    public function test_pipeline_exposes_all_five_states(): void
    {
        $repo = new DashboardRepository($this->pdo, 1);

        self::assertEqualsCanonicalizing(
            ['New', 'Review', 'Qualified', 'Disqualified', 'Converted'],
            $repo->states()
        );
    }

    /**
     * FR-DASH-001 - per-state counts are tenant-scoped and accurate.
     */
    public function test_lead_status_counts_are_scoped_and_accurate(): void
    {
        $this->seedTenant(1, ['New' => 2, 'Review' => 1, 'Converted' => 3]);
        $this->seedTenant(2, ['New' => 50]); // different tenant - must not leak in

        $view = (new DashboardController($this->pdo, 1))->forUser(tenantId: 1, role: 'staff');
        $counts = $view->leadStatusCounts();

        self::assertSame(2, $counts['New']);
        self::assertSame(1, $counts['Review']);
        self::assertSame(3, $counts['Converted']);
        self::assertSame(0, $counts['Qualified']);
        self::assertSame(0, $counts['Disqualified']);
    }

    /**
     * LBR-5.8 - the "awaiting human" queue lists only pending analyses for the
     * tenant, and excludes completed/failed ones.
     */
    public function test_dashboard_shows_awaiting_human_queue(): void
    {
        $this->seedTenant(1, ['New' => 1]);
        $leadId = $this->lastLeadId(1);
        $this->insert($this->pdo, 1, "INSERT INTO lead_ai_analyses (tenant_id, lead_id, status) VALUES (1, {$leadId}, 'pending')");
        $this->insert($this->pdo, 1, "INSERT INTO lead_ai_analyses (tenant_id, lead_id, status) VALUES (1, {$leadId}, 'complete')");

        $view = (new DashboardController($this->pdo, 1))->forUser(tenantId: 1, role: 'staff');
        $awaiting = $view->awaitingHuman();

        self::assertNotEmpty($awaiting);
        foreach ($awaiting as $row) {
            self::assertSame('pending', $row['status']);
        }
    }

    /**
     * AC-001 - tenant 1's awaiting-human queue excludes tenant 2's pending
     * analyses. Proves the scoping is real, not just cosmetic.
     */
    public function test_awaiting_human_is_tenant_scoped(): void
    {
        $this->seedTenant(2, ['New' => 1]);
        $leadId = $this->lastLeadId(2);
        $this->insert($this->pdo, 2, "INSERT INTO lead_ai_analyses (tenant_id, lead_id, status) VALUES (2, {$leadId}, 'pending')");

        $view = (new DashboardController($this->pdo, 1))->forUser(tenantId: 1, role: 'staff');
        self::assertSame([], $view->awaitingHuman());
    }

    /**
     * LBR-5.8 - the failed-delivery queue surfaces real failed deliveries
     * (migration 009 introduced the status/error columns that make this data
     * real rather than invented).
     */
    public function test_dashboard_shows_failed_deliveries(): void
    {
        $this->seedTenant(1, ['New' => 1]);
        $leadId = $this->lastLeadId(1);
        $this->insert(
            $this->pdo,
            1,
            "INSERT INTO message_deliveries (tenant_id, lead_id, kind, channel, recipient, body, status, error) "
            . "VALUES (1, {$leadId}, 'notification', 'email', 'a@example.com', 'body', 'failed', 'invalid recipient')"
        );

        $view = (new DashboardController($this->pdo, 1))->forUser(tenantId: 1, role: 'staff');
        $failed = $view->failedDeliveries();

        self::assertNotEmpty($failed);
        self::assertSame('failed', $failed[0]['status']);
        self::assertStringContainsString('invalid recipient', (string) $failed[0]['error']);
    }

    /**
     * AC-001 - tenant 1 cannot see tenant 2's failed deliveries.
     */
    public function test_failed_deliveries_are_tenant_scoped(): void
    {
        $this->seedTenant(2, ['New' => 1]);
        $leadId = $this->lastLeadId(2);
        $this->insert(
            $this->pdo,
            2,
            "INSERT INTO message_deliveries (tenant_id, lead_id, kind, channel, recipient, body, status, error) "
            . "VALUES (2, {$leadId}, 'notification', 'email', 'b@example.com', 'body', 'failed', 'boom')"
        );

        $view = (new DashboardController($this->pdo, 1))->forUser(tenantId: 1, role: 'staff');
        self::assertSame([], $view->failedDeliveries());
    }

    /**
     * @param array<string, int> $byStatus state => count to seed.
     */
    private function seedTenant(int $tenantId, array $byStatus): void
    {
        // The leads table has a FK to tenants(id); create the tenant row first
        // (INSERT IGNORE keeps re-application idempotent within the transaction).
        $this->insert(
            $this->pdo,
            $tenantId,
            "INSERT IGNORE INTO tenants (id, slug, name, status, deployment_model) "
            . "VALUES ({$tenantId}, 'tenant-{$tenantId}', 'Tenant {$tenantId}', 'active', 'cloud')"
        );

        foreach ($byStatus as $status => $n) {
            for ($i = 0; $i < $n; $i++) {
                $correlation = bin2hex(random_bytes(8)) . $tenantId . $i;
                $this->insert(
                    $this->pdo,
                    $tenantId,
                    "INSERT INTO leads (tenant_id, correlation_id, email, name, status) "
                    . "VALUES ({$tenantId}, '{$correlation}', 'u{$i}@example.com', 'User {$i}', '{$status}')"
                );
            }
        }
    }

    private function lastLeadId(int $tenantId): int
    {
        $statement = $this->pdo->prepare('SELECT id FROM leads WHERE tenant_id = :t ORDER BY id DESC LIMIT 1');
        $statement->bindValue('t', $tenantId, PDO::PARAM_INT);
        $statement->execute();

        return (int) $statement->fetchColumn();
    }

    private function insert(PDO $pdo, int $tenantId, string $sql): void
    {
        // Tests are exempt from the NoUnscopedClientQueryRule: seeding cross-row
        // fixtures is part of the evidence, not a client-data access path.
        $pdo->exec($sql);
    }
}
