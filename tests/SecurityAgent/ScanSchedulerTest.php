<?php

declare(strict_types=1);

namespace App\Tests\SecurityAgent;

use App\Audit\AuditLogger;
use App\SecurityAgent\AuthorizationRepository;
use App\SecurityAgent\ScanRepository;
use App\SecurityAgent\ScanScheduler;
use App\SecurityAgent\SecurityScan;
use DateTimeImmutable;
use DateTimeZone;
use App\Tests\TestCase;

/**
 * Recurring-scan scheduler (P3 close-out: FRD 2.36 "One-time/recurring jobs";
 * SFR-AUTH-001 "validity period ... before scheduling").
 *
 * TDD: the tests below were written against the contract, then the
 * implementation made them green. The falsification probes (P4-style) sabotage a
 * guard in src/ and confirm the RIGHT test goes red, proving the guarantee is
 * enforced rather than asserted.
 */
final class ScanSchedulerTest extends TestCase
{
    private const TZ = 'UTC';

    private function at(string $s): DateTimeImmutable
    {
        return new DateTimeImmutable($s, new DateTimeZone(self::TZ));
    }

    private function repo(int $tenantId = 1): ScanRepository
    {
        return new ScanRepository($this->pdo, $tenantId);
    }

    private function scheduler(int $tenantId = 1): ScanScheduler
    {
        return new ScanScheduler($this->repo($tenantId), new AuditLogger($this->pdo), $tenantId);
    }

    /** Seeds a tenant row so a second-tenant recurrence has a valid FK parent. */
    private function seedTenant(int $tenantId, string $slug): void
    {
        $this->pdo->prepare(
            'INSERT INTO tenants (id, slug, name) VALUES (:id, :slug, :name)'
            . ' ON DUPLICATE KEY UPDATE slug = :slug_u, name = :name_u'
        )->execute([
            'id' => $tenantId,
            'slug' => $slug,
            'name' => $slug,
            'slug_u' => $slug,
            'name_u' => $slug,
        ]);
    }

    /** Seeds an authorization id the FK on security_scans wants to point at. */
    private function authorizationId(int $tenantId = 1, int $id = 1): int
    {
        $repo = new AuthorizationRepository($this->pdo, $tenantId);
        $created = $repo->create(
            'Seed Client ' . $id,
            ['tls-config'],
            'soc@example.com',
            'dns',
            'proof-' . $id,
            $this->at('2026-01-01 00:00:00'),
            $this->at('2026-12-31 00:00:00'),
            null // no credential -> skips the credential store
        );

        // Force the deterministic id the tests reference.
        $this->pdo->prepare(
            'UPDATE security_authorizations SET id = :id, status = :status WHERE id = :created'
        )->execute(['id' => $id, 'status' => 'active', 'created' => $created]);

        return $id;
    }

    // =========================================================================
    // THE PINNING TEST — keeps the RATIFIED policy honest.
    // Sourced to NIST SP 800-53 Rev 5 CA-7 / SC-8 and OWASP ASVS 5.0 V14.3.
    // =========================================================================
    public function test_shipped_scan_schedule_policy_pins_its_contract_terms(): void
    {
        $path = dirname(__DIR__, 2) . '/config/security/SCAN_SCHEDULE_POLICY.php';
        $policy = require $path;

        self::assertIsArray($policy, 'Policy must return an array.');
        self::assertSame('RATIFIED', $policy['status'] ?? null, 'Policy is ratified; an unsourced value change must still fail CI.');
        self::assertSame(['daily', 'weekly', 'monthly'], $policy['allowed_cadences']);
        self::assertSame('weekly', $policy['default_cadence']);
        self::assertSame(365, $policy['max_validity_days']);
        self::assertSame(12, $policy['max_horizon_runs']);
        self::assertNotEmpty($policy['source_reference']);
    }

    // =========================================================================
    // FRD 2.36 / SFR-AUTH-001 — the validity-period guard fails closed.
    // =========================================================================
    public function test_recurring_schedule_refuses_a_lapsed_validity_period(): void
    {
        $auth = $this->authorizationId();
        $now = $this->at('2026-04-01 00:00:00');
        // Validity ended yesterday.
        $lapsed = $this->at('2026-03-31 00:00:00');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/validity period has already lapsed/');

        $this->scheduler()->scheduleRecurring(
            $auth,
            1,      // profileId
            1,      // profileVersion
            ScanRepository::RECURRENCE_WEEKLY,
            $lapsed,
            $now
        );
    }

    public function test_recurring_schedule_refuses_a_disallowed_cadence(): void
    {
        $auth = $this->authorizationId();
        $now = $this->at('2026-04-01 00:00:00');
        $future = $this->at('2026-12-31 00:00:00');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/not permitted by policy/');

        $this->scheduler()->scheduleRecurring($auth, 1, 1, 'fortnightly', $future, $now);
    }

    public function test_recurring_schedule_records_a_due_scan_with_validity_window(): void
    {
        $auth = $this->authorizationId();
        $now = $this->at('2026-04-01 00:00:00');
        $future = $this->at('2026-12-31 00:00:00');

        $scanId = $this->scheduler()->scheduleRecurring(
            $auth,
            1,
            1,
            ScanRepository::RECURRENCE_WEEKLY,
            $future,
            $now
        );

        $scan = $this->repo()->findById($scanId);
        self::assertNotNull($scan);
        self::assertTrue($scan->isRecurring());
        self::assertSame(ScanRepository::RECURRENCE_WEEKLY, $scan->recurrence());
        self::assertNotNull($scan->nextRunAt());
        self::assertNotNull($scan->validUntil());
        // next_run_at is the first weekly step from $now.
        self::assertSame('2026-04-08 00:00:00', $scan->nextRunAt()->format('Y-m-d H:i:s'));
        self::assertSame('2026-12-31 00:00:00', $scan->validUntil()->format('Y-m-d H:i:s'));

        // The schedule act is audited (SFR-AUD-001). Assert on object_id, not
        // detail — AuditLogger redacts high-entropy free text (SFR-AUTH-003).
        $rows = $this->auditRowsFor(ScanScheduler::AUDIT_SCHEDULED_RECURRING);
        self::assertCount(1, $rows);
        self::assertSame((string) $scanId, $rows[0]['object_id']);
    }

    // =========================================================================
    // dueScans — the worker-facing query. Expired recurrences must NOT surface.
    // =========================================================================
    public function test_due_scans_excludes_expired_and_terminal_rows(): void
    {
        $auth = $this->authorizationId();
        $now = $this->at('2026-04-10 00:00:00');

        // A) due + valid -> returned
        $dueId = $this->repo()->scheduleRecurring(
            $auth,
            1,
            1,
            ScanRepository::RECURRENCE_WEEKLY,
            $this->at('2026-12-31 00:00:00'),
            $this->at('2026-04-01 00:00:00'),
            null
        );
        // B) due but EXPIRED -> excluded
        $expired = $this->repo()->scheduleRecurring(
            $auth,
            1,
            1,
            ScanRepository::RECURRENCE_WEEKLY,
            $this->at('2026-04-05 00:00:00'),
            $this->at('2026-04-01 00:00:00'),
            null
        );
        // C) not yet due -> excluded
        $future = $this->repo()->scheduleRecurring(
            $auth,
            1,
            1,
            ScanRepository::RECURRENCE_WEEKLY,
            $this->at('2026-12-31 00:00:00'),
            $this->at('2026-05-01 00:00:00'),
            null
        );
        // D) one-shot (recurrence none) -> excluded
        $oneshot = $this->repo()->schedule($auth, 1, 1);

        $due = $this->repo()->dueScans($now);
        $ids = array_map(static fn (SecurityScan $s): int => $s->id(), $due);

        self::assertContains($dueId, $ids, 'The valid, due recurrence must surface.');
        self::assertNotContains($expired, $ids, 'An expired recurrence must NOT surface.');
        self::assertNotContains($future, $ids, 'A not-yet-due recurrence must NOT surface.');
        self::assertNotContains($oneshot, $ids, 'A one-shot scan is not a recurrence.');
    }

    public function test_due_scans_is_tenant_scoped(): void
    {
        $this->seedTenant(2, 'tenant-2');
        $this->authorizationId(1, 1);
        $this->authorizationId(2, 2);

        // Tenant 2 recurrence.
        $this->repo(2)->scheduleRecurring(
            2,
            1,
            1,
            ScanRepository::RECURRENCE_DAILY,
            $this->at('2026-12-31 00:00:00'),
            $this->at('2026-04-01 00:00:00'),
            null
        );

        $due = $this->repo(1)->dueScans($this->at('2026-04-10 00:00:00'));
        self::assertSame([], $due, 'Tenant 1 must not see tenant 2 recurrences (AC-001).');
    }

    // =========================================================================
    // rollForward — pure cadence math, no clock.
    // =========================================================================
    public function test_roll_forward_advances_by_cadence_interval(): void
    {
        $from = $this->at('2026-04-01 00:00:00');
        self::assertSame('2026-04-02 00:00:00', ScanRepository::rollForward(ScanRepository::RECURRENCE_DAILY, $from)->format('Y-m-d H:i:s'));
        self::assertSame('2026-04-08 00:00:00', ScanRepository::rollForward(ScanRepository::RECURRENCE_WEEKLY, $from)->format('Y-m-d H:i:s'));
        self::assertSame('2026-05-01 00:00:00', ScanRepository::rollForward(ScanRepository::RECURRENCE_MONTHLY, $from)->format('Y-m-d H:i:s'));
    }

    public function test_roll_forward_rejects_unknown_cadence(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        ScanRepository::rollForward('yearly', $this->at('2026-04-01 00:00:00'));
    }

    // ---- audit helper -------------------------------------------------------
    /**
     * @return array<int, array<string, mixed>>
     */
    private function auditRowsFor(string $action): array
    {
        $statement = $this->pdo->prepare(
            'SELECT object_id FROM audit_events WHERE action = :action AND ' . \App\Tenancy\TenantScope::COLUMN . ' = :t'
        );
        $statement->bindValue('action', $action);
        $statement->bindValue('t', 1);
        $statement->execute();

        return $statement->fetchAll(\PDO::FETCH_ASSOC);
    }
}
