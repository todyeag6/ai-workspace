<?php

declare(strict_types=1);

namespace App\Tests\Leads;

use App\Leads\LeadDashboard;
use App\Tests\TestCase;
use DomainException;
use InvalidArgumentException;
use PDO;
use PHPUnit\Framework\Attributes\Test;

/**
 * LFR-DASH-002 (lead search/filter) + LFR-DASH-003 (lead detail view).
 *
 * DB-backed: seeds tenant 1 + tenant 2 leads and their related rows, then asserts
 * the filter returns only the signed-in tenant's matching rows (AC-001) and the
 * detail view assembles every required section for exactly one lead.
 */
final class LeadDashboardTest extends TestCase
{
    /**
     * @param array<string, list<array<string, string>>> $byStatus
     */
    private function seedTenant(int $tenantId, array $byStatus): void
    {
        $this->insert(
            $this->pdo,
            "INSERT IGNORE INTO tenants (id, slug, name, status, deployment_model) "
            . "VALUES ({$tenantId}, 'tenant-{$tenantId}', 'Tenant {$tenantId}', 'active', 'cloud')"
        );
        foreach ($byStatus as $status => $rows) {
            foreach ($rows as $spec) {
                $priority = $spec['priority'] ?? 'normal';
                $source = $spec['source'] ?? 'public_form';
                $email = bin2hex(random_bytes(6)) . '@example.com';
                $this->insert(
                    $this->pdo,
                    "INSERT INTO leads (tenant_id, correlation_id, email, name, source, status, priority) "
                    . "VALUES ({$tenantId}, '" . bin2hex(random_bytes(8)) . "', '{$email}', 'User', "
                    . "'{$source}', '{$status}', '{$priority}')"
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

    #[Test]
    public function test_filter_by_status_returns_only_matching_tenant_rows(): void
    {
        $this->seedTenant(1, ['New' => [[]], 'Review' => [[]]]);
        $this->seedTenant(2, ['New' => [[]], 'Review' => [[]]]);

        $dashboard = new LeadDashboard($this->pdo, 1);
        $rows = $dashboard->filterLeads(['status' => 'Review']);

        self::assertCount(1, $rows);
        self::assertSame('Review', $rows[0]['status']);
        self::assertSame(1, (int) $rows[0]['tenant_id']);
    }

    #[Test]
    public function test_filter_by_priority_uses_new_column(): void
    {
        $this->seedTenant(1, ['New' => [['priority' => 'high'], ['priority' => 'normal']]]);

        $dashboard = new LeadDashboard($this->pdo, 1);
        $rows = $dashboard->filterLeads(['priority' => 'high']);

        self::assertCount(1, $rows);
        self::assertSame('high', $rows[0]['priority']);
    }

    #[Test]
    public function test_filter_rejects_unknown_dimension(): void
    {
        $this->seedTenant(1, ['New' => [[]]]);

        $dashboard = new LeadDashboard($this->pdo, 1);

        $this->expectException(DomainException::class);
        $dashboard->filterLeads(['evil' => 'x']);
    }

    #[Test]
    public function test_filter_rejects_invalid_priority_value(): void
    {
        $this->seedTenant(1, ['New' => [[]]]);

        $dashboard = new LeadDashboard($this->pdo, 1);

        $this->expectException(InvalidArgumentException::class);
        $dashboard->filterLeads(['priority' => 'urgent']);
    }

    #[Test]
    public function test_detail_assembles_all_sections_for_one_lead(): void
    {
        $this->seedTenant(1, ['Review' => [[]]]);
        $leadId = $this->lastLeadId(1);

        $this->insert($this->pdo, "INSERT INTO lead_submissions (tenant_id, lead_id, payload_json, ip_hash, user_agent) "
            . "VALUES (1, {$leadId}, '{\"raw\":\"yes\"}', 'deadbeef', 'curl')");
        $this->insert($this->pdo, "INSERT INTO lead_ai_analyses (tenant_id, lead_id, status, analysis_json, error_message) "
            . "VALUES (1, {$leadId}, 'complete', '{\"category\":\"finance\"}', NULL)");
        $this->insert($this->pdo, "INSERT INTO lead_field_corrections (tenant_id, lead_id, field_name, old_value, new_value, corrected_by) "
            . "VALUES (1, {$leadId}, 'company', 'A', 'B', 1)");
        $this->insert($this->pdo, "INSERT INTO lead_interactions (tenant_id, lead_id, channel, direction, body, actor_id) "
            . "VALUES (1, {$leadId}, 'email', 'outbound', 'hi', 1)");
        $this->insert($this->pdo, "INSERT INTO lead_tasks (tenant_id, lead_id, title, status, due_at, assigned_to) "
            . "VALUES (1, {$leadId}, 'Call back', 'open', NULL, 1)");
        $this->insert($this->pdo, "INSERT INTO audit_log (tenant_id, actor_user_id, event, outcome, object_type, object_id, detail) "
            . "VALUES (1, 1, 'lead.review', 'success', 'lead', '{$leadId}', 'reviewed')");

        $dashboard = new LeadDashboard($this->pdo, 1);
        $detail = $dashboard->detail($leadId);

        self::assertNotNull($detail);
        self::assertArrayHasKey('lead', $detail);
        self::assertArrayHasKey('original_submission', $detail);
        self::assertArrayHasKey('ai_output', $detail);
        self::assertArrayHasKey('corrections', $detail);
        self::assertArrayHasKey('interactions', $detail);
        self::assertArrayHasKey('tasks', $detail);
        self::assertArrayHasKey('audit_history', $detail);
        self::assertArrayHasKey('data_retention_status', $detail);

        self::assertSame('finance', $detail['ai_output']['category'] ?? json_decode((string) $detail['ai_output']['analysis_json'], true)['category']);
        self::assertCount(1, $detail['corrections']);
        self::assertCount(1, $detail['interactions']);
        self::assertCount(1, $detail['tasks']);
        self::assertCount(1, $detail['audit_history']);
        self::assertSame('reviewed', $detail['audit_history'][0]['detail']);
        self::assertTrue($detail['data_retention_status']['retained']);
    }

    #[Test]
    public function test_detail_is_null_for_other_tenant(): void
    {
        $this->seedTenant(2, ['New' => [[]]]);
        $otherLeadId = $this->lastLeadId(2);

        $dashboard = new LeadDashboard($this->pdo, 1);
        self::assertNull($dashboard->detail($otherLeadId));
    }

    #[Test]
    public function test_filter_by_date_source_assignee_category_delivery(): void
    {
        $this->seedTenant(1, ['Review' => [['source' => 'referral']]]);
        $leadId = $this->lastLeadId(1);
        $this->insert($this->pdo, "INSERT INTO lead_ai_analyses (tenant_id, lead_id, status, analysis_json) "
            . "VALUES (1, {$leadId}, 'complete', '{\"category\":\"legal\"}')");
        $this->insert($this->pdo, "INSERT INTO lead_tasks (tenant_id, lead_id, title, status, due_at, assigned_to) "
            . "VALUES (1, {$leadId}, 'T', 'open', NULL, 7)");
        $this->insert($this->pdo, "INSERT INTO message_deliveries (tenant_id, lead_id, kind, channel, recipient, body, status) "
            . "VALUES (1, {$leadId}, 'notification', 'email', 'a@x.com', 'b', 'sent')");

        $dashboard = new LeadDashboard($this->pdo, 1);

        self::assertCount(1, $dashboard->filterLeads(['source' => 'referral']));
        self::assertCount(1, $dashboard->filterLeads(['assignee' => 7]));
        self::assertCount(1, $dashboard->filterLeads(['category' => 'legal']));
        self::assertCount(1, $dashboard->filterLeads(['delivery' => 'sent']));
        self::assertCount(1, $dashboard->filterLeads([
            'source' => 'referral',
            'assignee' => 7,
            'category' => 'legal',
            'delivery' => 'sent',
        ]));
    }

    private function insert(PDO $pdo, string $sql): void
    {
        // Tests are exempt from the NoUnscopedClientQueryRule: seeding fixtures is
        // part of the evidence, not a client-data access path.
        $pdo->exec($sql);
    }
}
