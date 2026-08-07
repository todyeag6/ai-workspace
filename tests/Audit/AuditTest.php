<?php

declare(strict_types=1);

namespace App\Tests\Audit;

use App\Audit\AuditLogger;
use App\Tests\TestCase;
use PDOException;

/**
 * Immutable audit event log (FR-AUD-001/002).
 *
 * FR-AUD-001  every security-relevant action leaves a complete record - who,
 *             in which tenant, what they did, how it turned out, where it came
 *             from (source), and a correlation id that lets events be stitched
 *             together across services. The append-only guarantee is enforced
 *             TWICE: the application never offers an update/delete path, AND a
 *             pair of MySQL BEFORE UPDATE / BEFORE DELETE triggers refuse any
 *             attempt at the database layer. Discipline alone cannot satisfy
 *             "append-only" - the database has to refuse.
 * FR-AUD-002  secrets are never persisted to the audit trail. Anything that
 *             looks like a credential (token, api key, password) is redacted
 *             before the row is written, so a database disclosure does not hand
 *             over usable secrets via the audit table.
 *
 * © AI WebScapes 2026
 */
final class AuditTest extends TestCase
{
    private const TENANT_ID = 1;

    private AuditLogger $audit;

    protected function setUp(): void
    {
        parent::setUp();
        $this->audit = new AuditLogger($this->pdo);
    }

    public function test_audit_records_all_required_fields(): void
    {
        $id = $this->audit->record(
            tenantId: self::TENANT_ID,
            actorUserId: 1,
            action: 'lead.update',
            objectType: 'lead',
            objectId: 'lead-1',
            outcome: 'success',
            source: 'api',
            correlationId: 'c1',
            versions: ['lead:v2']
        );

        $row = $this->row((int) $id);

        // The full chain of custody the plan requires, each present.
        $this->assertNotNull($row['actor_user_id'], 'the acting user is recorded');
        $this->assertSame(self::TENANT_ID, (int) $row['tenant_id'], 'the tenant is recorded');
        $this->assertNotNull($row['action'], 'the action is recorded');
        $this->assertNotNull($row['object_id'], 'the object is recorded');
        $this->assertNotNull($row['occurred_at'], 'a timestamp is recorded');
        $this->assertSame('success', $row['outcome'], 'the outcome is recorded');
        $this->assertSame('api', $row['source'], 'the source is recorded');
        $this->assertSame('c1', $row['correlation_id'], 'the correlation id is recorded');
        $this->assertStringContainsString('lead:v2', (string) $row['versions'], 'version lineage is recorded');
    }

    public function test_secrets_never_written_to_audit(): void
    {
        $id = $this->audit->record(
            tenantId: self::TENANT_ID,
            actorUserId: 1,
            action: 'webhook.received',
            objectType: 'integration',
            objectId: 'x',
            outcome: 'success',
            source: 'api',
            detail: 'callback token=supersecret and apikey=also-secret',
            versions: ['payload' => ['token' => 'supersecret', 'id' => 'ok']]
        );

        // The raw row, exactly as stored - no redaction applied at read time.
        $raw = json_encode($this->row((int) $id), JSON_THROW_ON_ERROR);

        $this->assertStringNotContainsString('supersecret', $raw, 'FR-AUD-002: a secret is never persisted');
        $this->assertStringNotContainsString('also-secret', $raw, 'FR-AUD-002: every credential shape is scrubbed');
        $this->assertStringContainsString('[REDACTED]', $raw, 'the secret is replaced, not merely dropped');
    }

    public function test_audit_rows_are_immutable(): void
    {
        $id = $this->audit->record(
            tenantId: self::TENANT_ID,
            actorUserId: 1,
            action: 'lead.view',
            objectType: 'lead',
            objectId: 'lead-9',
            outcome: 'success',
            source: 'api'
        );

        // The application layer offers no update path; the database layer (the
        // BEFORE UPDATE trigger) must refuse the mutation outright.
        $this->expectException(PDOException::class);
        $this->pdo->exec(sprintf('UPDATE audit_events SET action = "tampered" WHERE id = %d', (int) $id));
    }

    public function test_audit_rows_cannot_be_deleted(): void
    {
        $id = $this->audit->record(
            tenantId: self::TENANT_ID,
            actorUserId: 1,
            action: 'lead.view',
            objectType: 'lead',
            objectId: 'lead-9',
            outcome: 'success',
            source: 'api'
        );

        $this->expectException(PDOException::class);
        $this->pdo->exec(sprintf('DELETE FROM audit_events WHERE id = %d', (int) $id));
    }

    /**
     * @return array<string, mixed>
     */
    private function row(int $id): array
    {
        $statement = $this->pdo->prepare('SELECT * FROM audit_events WHERE id = :id');
        $statement->execute(['id' => $id]);
        $row = $statement->fetch(\PDO::FETCH_ASSOC);

        return is_array($row) ? $row : [];
    }
}
