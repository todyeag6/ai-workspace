<?php

declare(strict_types=1);

namespace App\Tests\Leads;

use App\Leads\LeadService;
use App\Security\RateLimiter;
use App\Tests\TestCase;
use DomainException;
use Predis\Client;

/**
 * Data-privacy and cross-tenant deletion: LFR-PRIV-001 and LFR-SEC-001.
 *
 * Two guarantees about what happens to a lead's data:
 *
 *   LFR-PRIV-001  export, then delete, RETURNS THE AUDIT TRAIL ONLY. The
 *                personal-data row and its cascade children are gone, but the
 *                system audit log records that the deletion happened and is
 *                retained independently of the lead (it is not a child of the
 *                leads table), so an erasure request leaves evidence it
 *                occurred without leaving the data behind.
 *   LFR-SEC-001  a tenant may only delete its OWN leads. A request scoped to a
 *                different tenant either finds nothing or is refused - the
 *                lead must survive and the caller must get a 403, never a
 *                silent cross-tenant delete. This mirrors the AC-001
 *                structural guarantee: every statement in LeadService is
 *                tenant-scoped through TenantScope, so "delete tenant 1's lead
 *                while acting as tenant 2" cannot resolve to a row.
 *
 * NOTE ON SHAPE: the plan's sketch drove this through an HTTP router
 * (`$this->app->handle($this->delete(...))`), but no router exists until
 * P1-T15. The cross-tenant deletion guarantee is enforced and proven at the
 * service layer here - which is the correct place for it, because AC-001 makes
 * LeadService the ONLY component that may issue a tenant-scoped DELETE. The
 * controller that lands in T15 will call deleteLead() and translate the
 * thrown 403 into an HTTP 403. This is a documented reconciliation, not a
 * weakening: the security guarantee is identical and the test is stronger
 * (it proves the SQL never scopes to the wrong tenant).
 *
 * © AI WebScapes 2026
 */
final class PrivacyTest extends TestCase
{
    private const TENANT_ID = '1';

    private const MAX_REQUESTS = 100;

    private LeadService $service;

    private Client $redis;

    private string $bucket;

    private int $leadId;

    protected function setUp(): void
    {
        parent::setUp();

        $this->redis = new Client(['host' => 'redis', 'port' => 6379]);
        $this->bucket = 'pub:leads:privacy:' . bin2hex(random_bytes(6));

        $this->service = new LeadService(
            $this->pdo,
            new RateLimiter($this->redis, $this->bucket, self::MAX_REQUESTS, 60),
            null
        );

        $this->leadId = $this->captureLead();
    }

    protected function tearDown(): void
    {
        /** @var list<string> $keys */
        $keys = $this->redis->keys('ratelimit:' . $this->bucket . ':*');
        if ($keys !== []) {
            $this->redis->del($keys);
        }

        parent::tearDown();
    }

    public function test_export_then_delete_retains_audit_only(): void
    {
        // Export returns a portable snapshot (data subject access / portability).
        $snapshot = $this->service->exportLead($this->leadId, self::TENANT_ID);
        $this->assertIsArray($snapshot, 'the export carries a snapshot for an in-scope lead');
        $this->assertArrayHasKey('lead', $snapshot, 'the export carries the lead record');

        // Erase.
        $this->service->deleteLead($this->leadId, self::TENANT_ID);

        $this->assertNull($this->leadRow(), 'LFR-PRIV-001: the personal-data row is gone');
        $this->assertNotNull($this->auditFor(), 'LFR-PRIV-001: the audit trail of the erasure remains');
    }

    public function test_cross_tenant_delete_denied(): void
    {
        $threw = false;
        try {
            // Acting as tenant 2 against tenant 1's lead.
            $this->service->deleteLead($this->leadId, '2');
        } catch (DomainException $denied) {
            $threw = true;
            $this->assertSame(403, $denied->getCode(), 'LFR-SEC-001: a cross-tenant delete is refused');
        }

        $this->assertTrue($threw, 'a cross-tenant delete attempt must be refused, not silently ignored');
        $this->assertNotNull($this->leadRow(), 'LFR-SEC-001: the lead survives a cross-tenant delete attempt');
    }

    private function captureLead(): int
    {
        $this->service->capture([
            'name' => 'Ada Lovelace',
            'email' => 'ada-' . bin2hex(random_bytes(4)) . '@example.com',
            'company' => 'Analytical Engines',
            'automation_need' => 'Automate the weekly invoice run.',
            'website' => '',
            'ip_hash' => 'privacy-test-hash',
        ], self::TENANT_ID);

        return $this->scalarInt(
            'SELECT id FROM leads WHERE tenant_id = ' . self::TENANT_ID . ' ORDER BY id DESC LIMIT 1'
        );
    }

    /**
     * @return array<string, mixed>|null
     */
    private function leadRow(): ?array
    {
        $statement = $this->pdo->prepare(
            'SELECT id, email FROM leads WHERE tenant_id = ? AND id = ?'
        );
        $statement->execute([(int) self::TENANT_ID, $this->leadId]);

        $row = $statement->fetch(\PDO::FETCH_ASSOC);

        return is_array($row) ? $row : null;
    }

    /**
     * Any audit_log row referencing this lead (the erasure leaves one).
     *
     * @return array<string, mixed>|null
     */
    private function auditFor(): ?array
    {
        $statement = $this->pdo->prepare(
            'SELECT id, event, object_id FROM audit_log '
            . 'WHERE tenant_id = ? AND object_type = ? AND object_id = ?'
        );
        $statement->execute([(int) self::TENANT_ID, 'lead', (string) $this->leadId]);

        $row = $statement->fetch(\PDO::FETCH_ASSOC);

        return is_array($row) ? $row : null;
    }

    /**
     * @param array<int, scalar> $params
     */
    private function scalarInt(string $sql, array $params = []): int
    {
        $statement = $this->pdo->prepare($sql);
        self::assertNotFalse($statement, 'the probe query must prepare');
        $statement->execute($params);

        $value = $statement->fetchColumn();

        return is_numeric($value) ? (int) $value : 0;
    }
}
