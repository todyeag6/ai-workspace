<?php

declare(strict_types=1);

namespace App\Tests\SecurityAgent;

use App\Audit\AuditLogger;
use App\SecurityAgent\AuthorizationRepository;
use App\SecurityAgent\KillSwitch;
use App\SecurityAgent\SafetyMonitor;
use App\SecurityAgent\ScanProfileRepository;
use App\SecurityAgent\ScanRepository;
use App\SecurityAgent\ScanScheduler;
use App\Tenancy\TenantScope;
use App\Tests\TestCase;
use DateTimeImmutable;
use PDO;
use RuntimeException;

/**
 * P3-T2 — Safety Monitor + Kill Switch (SFR-SAFE-001/002/003, SBR-3.3/3.5).
 *
 * Each test maps to a baseline requirement:
 *
 *  - SFR-SAFE-001: every scan enforces concurrency, request rate, timeout,
 *    payload size, retry and duration limits (P3 exit-gate acceptance test
 *    "Rate limit -> Observed requests do not exceed approved profile").
 *  - SFR-SAFE-002: an operator kill switch stops an active job immediately,
 *    and configured health/safety signals stop it automatically (P3 exit-gate
 *    acceptance test "Kill switch -> Active jobs stop within defined
 *    operational threshold").
 *  - SFR-SAFE-003 / SBR-3.3: destructive checks are OFF by default and need a
 *    separately approved profile before they may run.
 *  - SBR-3.5: the agent stops on safety thresholds, authorization expiry,
 *    scope mismatch or target instability (P3 exit-gate acceptance test
 *    "Target instability -> Safety monitor stops or pauses scan and alerts").
 *  - AC-001: none of the above is visible or reachable across a tenant
 *    boundary.
 *
 * WHY THE ASSERTIONS LOOK LIKE THIS. The monitor DECIDES; it does not act on a
 * socket. So each test asserts two things: the verdict handed back to the
 * caller, and the RECORD written for it. A refusal nobody can evidence would
 * satisfy neither the requirement nor the acceptance test.
 *
 * © AI WebScapes 2026
 */
final class SafetyMonitorTest extends TestCase
{
    // ---------------------------------------------------------------
    // SFR-SAFE-003 / SBR-3.3 — non-destructive by default
    // ---------------------------------------------------------------

    public function test_default_profile_non_destructive(): void
    {
        $this->seedTenant(1);
        $profiles = $this->profiles(1);

        // No destructive argument at all: the default is the safe one, so a
        // caller cannot get destructive behaviour by forgetting a flag.
        $id = $profiles->create($this->authorization(1), ['tls-config', 'http-headers']);
        $profile = $profiles->requireById($id);

        self::assertFalse($profile->isDestructiveEnabled(), 'Destructive checks must default to disabled.');
        self::assertFalse($profile->isDestructiveApproved());
        self::assertSame(['tls-config', 'http-headers'], $profile->checks());

        // SBR-3.3: the shipped defaults are rate-limited and single-threaded,
        // i.e. designed not to degrade the target.
        self::assertSame(1, $profile->concurrencyLimit());
        self::assertSame(60, $profile->rateLimitPerMin());
        self::assertSame(30, $profile->requestTimeoutSec());
        self::assertSame(3, $profile->maxRetries());
        self::assertSame(3600, $profile->maxDurationSec());
    }

    // ---------------------------------------------------------------
    // SFR-SAFE-003 — destructive checks need a SEPARATE approval
    // ---------------------------------------------------------------

    public function test_destructive_requires_separate_approval(): void
    {
        $this->seedTenant(1);
        $profiles = $this->profiles(1);
        $scans = $this->scans(1);
        $monitor = $this->monitor(1, $scans, $profiles);
        $authorizationId = $this->authorization(1);

        // Enabling is NOT approving: the two are deliberately separate acts.
        $profileId = $profiles->create($authorizationId, ['dos-probe'], destructiveChecksEnabled: true);
        $profile = $profiles->requireById($profileId);
        self::assertTrue($profile->isDestructiveEnabled());
        self::assertFalse($profile->isDestructiveApproved(), 'Enabling must not imply approval.');

        $scanId = $scans->schedule($authorizationId, $profileId, 1);
        $scans->start($scanId);

        // Until it is approved, the monitor refuses every request the scanner
        // asks about - and records why.
        $verdict = $monitor->assertRequestAllowed($scanId);
        self::assertFalse($verdict['allowed']);
        self::assertSame(SafetyMonitor::DENY_DESTRUCTIVE_UNAPPROVED, $verdict['reason']);
        self::assertSame(1, $this->scanEvents(1, $scanId, 'destructive_not_approved'));

        // The separate approval flips it, and is itself evidenced.
        $profiles->approveDestructiveChecks($profileId, 77);
        self::assertTrue($profiles->requireById($profileId)->isDestructiveApproved());
        self::assertSame(1, $this->auditEvents(1, 'secscan.destructive.approve'));
        self::assertTrue($monitor->assertRequestAllowed($scanId)['allowed']);

        // You cannot approve what was never enabled: approval is not a way to
        // turn destructive checks on behind the profile author's back.
        $plain = $profiles->create($authorizationId, ['tls-config']);
        $this->expectException(RuntimeException::class);
        $profiles->approveDestructiveChecks($plain, 77);
    }

    // ---------------------------------------------------------------
    // SFR-SAFE-002 + P3 exit-gate: "Kill switch -> Active jobs stop"
    // ---------------------------------------------------------------

    public function test_kill_switch_stops_active_job(): void
    {
        $this->seedTenant(1);
        $profiles = $this->profiles(1);
        $scans = $this->scans(1);
        $monitor = $this->monitor(1, $scans, $profiles);

        $authorizationId = $this->authorization(1);
        $profileId = $profiles->create($authorizationId, ['http-headers']);
        $scanId = $this->scheduler(1, $scans)->scheduleScan($authorizationId, $profileId, 1);
        $scans->start($scanId);

        self::assertTrue($scans->requireById($scanId)->isRunning());
        self::assertFalse($monitor->shouldStop($scanId));
        self::assertSame(1, $this->auditEvents(1, 'secscan.scheduled'));

        // The operator pulls the switch.
        self::assertTrue($this->killSwitch(1, $scans)->requestStop($scanId));

        // "Immediate" is a synchronous flag read: the next poll of the loop
        // that holds the socket sees it, with no queue or worker in between.
        self::assertTrue($this->killSwitch(1, $scans)->isStopRequested($scanId));
        self::assertTrue($monitor->shouldStop($scanId));
        self::assertTrue($scans->requireById($scanId)->shouldStop());

        // And the stop is evidenced, not merely effected.
        self::assertSame(1, $this->scanEvents(1, $scanId, 'kill_switch'));
        self::assertSame(1, $this->auditEvents(1, 'secscan.kill.requested'));

        // The very next request the scanner asks about is refused.
        $verdict = $monitor->assertRequestAllowed($scanId);
        self::assertFalse($verdict['allowed']);
        self::assertSame(SafetyMonitor::DENY_KILL, $verdict['reason']);
    }

    // ---------------------------------------------------------------
    // SFR-SAFE-001 + P3 exit-gate: "Observed requests do not exceed profile"
    // ---------------------------------------------------------------

    public function test_rate_limit_not_exceeded(): void
    {
        $this->seedTenant(1);
        $profiles = $this->profiles(1);
        $scans = $this->scans(1);
        $monitor = $this->monitor(1, $scans, $profiles);

        $authorizationId = $this->authorization(1);
        $profileId = $profiles->create($authorizationId, ['http-headers'], rateLimitPerMin: 3);
        $scanId = $scans->schedule($authorizationId, $profileId, 1);

        $now = new DateTimeImmutable('2026-06-01 12:00:00');
        $scans->start($scanId, $now);

        for ($i = 1; $i <= 3; $i++) {
            $verdict = $monitor->assertRequestAllowed($scanId, $now);
            self::assertTrue($verdict['allowed'], sprintf('Request %d is inside the approved rate.', $i));
            self::assertSame($i, $verdict['count']);
        }

        $refused = $monitor->assertRequestAllowed($scanId, $now);
        self::assertFalse($refused['allowed'], 'The 4th request in the window exceeds the approved profile.');
        self::assertSame(SafetyMonitor::DENY_RATE, $refused['reason']);
        self::assertSame(1, $this->scanEvents(1, $scanId, 'rate_exceeded'));

        // The acceptance criterion is about OBSERVED requests, so the refused
        // one must not have been counted either.
        self::assertSame(3, $scans->requireById($scanId)->observedRequests());
        self::assertSame(3, $refused['count']);

        // A new fixed window resets the allowance - the limit is per minute,
        // not per scan.
        $later = $now->modify('+61 seconds');
        $next = $monitor->assertRequestAllowed($scanId, $later);
        self::assertTrue($next['allowed']);
        self::assertSame(1, $next['count']);
    }

    // ---------------------------------------------------------------
    // SFR-SAFE-001 — concurrency and duration ceilings
    // ---------------------------------------------------------------

    public function test_concurrency_and_duration_limits_enforced(): void
    {
        $this->seedTenant(1);
        $profiles = $this->profiles(1);
        $scans = $this->scans(1);
        $monitor = $this->monitor(1, $scans, $profiles);

        $authorizationId = $this->authorization(1);
        $profileId = $profiles->create(
            $authorizationId,
            ['http-headers'],
            concurrencyLimit: 2,
            maxDurationSec: 600
        );
        $scanId = $scans->schedule($authorizationId, $profileId, 1);

        $now = new DateTimeImmutable('2026-06-01 12:00:00');
        $scans->start($scanId, $now);

        // Two workers in flight is exactly the ceiling, so still allowed.
        $scans->recordConcurrency($scanId, 2);
        $atCeiling = $monitor->assertRequestAllowed($scanId, $now);
        self::assertTrue($atCeiling['allowed'], 'Concurrency AT the ceiling is inside the envelope.');

        // A third exceeds it.
        $scans->recordConcurrency($scanId, 1);
        $refused = $monitor->assertRequestAllowed($scanId, $now->modify('+1 second'));
        self::assertFalse($refused['allowed']);
        self::assertSame(SafetyMonitor::DENY_CONCURRENCY, $refused['reason']);
        self::assertSame(1, $this->scanEvents(1, $scanId, 'concurrency_exceeded'));

        $scans->recordConcurrency($scanId, -2);

        // Past the agreed duration the scan is stopped, not merely refused.
        $tooLate = $now->modify('+601 seconds');
        $expired = $monitor->assertRequestAllowed($scanId, $tooLate);
        self::assertFalse($expired['allowed']);
        self::assertSame(SafetyMonitor::DENY_DURATION, $expired['reason']);
        self::assertSame(1, $this->scanEvents(1, $scanId, 'duration_exceeded'));
        self::assertSame('stopped', $scans->requireById($scanId)->status());
        self::assertTrue($monitor->shouldStop($scanId));
    }

    // ---------------------------------------------------------------
    // SBR-3.5 + P3 exit-gate: "Target instability -> pause and alert"
    // ---------------------------------------------------------------

    public function test_target_instability_pauses_and_alerts(): void
    {
        $this->seedTenant(1);
        $profiles = $this->profiles(1);
        $scans = $this->scans(1);
        $monitor = $this->monitor(1, $scans, $profiles);

        $authorizationId = $this->authorization(1);
        $profileId = $profiles->create($authorizationId, ['http-headers']);
        $scanId = $scans->schedule($authorizationId, $profileId, 1);
        $scans->start($scanId);

        // A healthy target changes nothing - the monitor is not trigger-happy.
        $healthy = $monitor->observeTargetInstability($scanId, 0.01, 120, 2000, 0.5);
        self::assertFalse($healthy['paused']);
        self::assertSame('running', $scans->requireById($scanId)->status());
        self::assertSame(0, $this->scanEvents(1, $scanId, 'instability_pause'));

        // An unstable one pauses the scan AND alerts.
        $unstable = $monitor->observeTargetInstability($scanId, 0.9, 5000, 2000, 0.5);

        self::assertTrue($unstable['paused']);
        self::assertSame('paused', $scans->requireById($scanId)->status());
        self::assertSame(1, $this->scanEvents(1, $scanId, 'instability_pause'));
        self::assertSame(1, $this->auditEvents(1, 'secscan.instability.alert'));

        // A paused scan stops the loop that holds the socket.
        self::assertTrue($monitor->shouldStop($scanId));
    }

    // ---------------------------------------------------------------
    // SBR-3.5 — automatic stop on authorization expiry / scope mismatch
    // ---------------------------------------------------------------

    public function test_auto_stop_on_authorization_expiry(): void
    {
        $this->seedTenant(1);
        $scans = $this->scans(1);
        $monitor = $this->monitor(1, $scans, $this->profiles(1));
        $scanId = $this->runningScan(1, $scans);

        $result = $monitor->autoStopOnSignals($scanId, authorizationExpired: true, scopeMismatch: false);

        self::assertTrue($result['stopped']);
        self::assertSame('auth_expired', $result['reason']);
        self::assertSame('stopped', $scans->requireById($scanId)->status());
        self::assertSame(1, $this->scanEvents(1, $scanId, 'auth_expired'));
        self::assertTrue($monitor->shouldStop($scanId));
    }

    public function test_auto_stop_on_scope_mismatch(): void
    {
        $this->seedTenant(1);
        $scans = $this->scans(1);
        $monitor = $this->monitor(1, $scans, $this->profiles(1));
        $scanId = $this->runningScan(1, $scans);

        // Neither signal raised: a running scan keeps running.
        self::assertFalse($monitor->autoStopOnSignals($scanId, false, false)['stopped']);
        self::assertSame('running', $scans->requireById($scanId)->status());

        $result = $monitor->autoStopOnSignals($scanId, false, true);

        self::assertTrue($result['stopped']);
        self::assertSame('scope_mismatch', $result['reason']);
        self::assertSame('stopped', $scans->requireById($scanId)->status());
        self::assertSame(1, $this->scanEvents(1, $scanId, 'scope_mismatch'));
    }

    // ---------------------------------------------------------------
    // SFR-SAFE-001 — payload size ceiling
    // ---------------------------------------------------------------

    public function test_payload_size_enforced(): void
    {
        $this->seedTenant(1);
        $profiles = $this->profiles(1);
        $scans = $this->scans(1);
        $monitor = $this->monitor(1, $scans, $profiles);

        $authorizationId = $this->authorization(1);
        $profileId = $profiles->create(
            $authorizationId,
            ['http-headers'],
            maxPayloadBytes: 1024,
            maxRetries: 2,
            requestTimeoutSec: 15
        );
        $scanId = $scans->schedule($authorizationId, $profileId, 1);
        $scans->start($scanId);

        self::assertTrue($monitor->enforcePayloadSize($scanId, 512)['allowed']);
        self::assertSame(0, $this->scanEvents(1, $scanId, 'payload_exceeded'));

        $refused = $monitor->enforcePayloadSize($scanId, 2048);
        self::assertFalse($refused['allowed']);
        self::assertSame(SafetyMonitor::DENY_PAYLOAD, $refused['reason']);
        self::assertSame(2048, $refused['bytes']);
        self::assertSame(1, $this->scanEvents(1, $scanId, 'payload_exceeded'));

        // The remaining two limits SFR-SAFE-001 names: retries and timeout.
        self::assertTrue($monitor->assertRetryAllowed($scanId, 2)['allowed']);
        $tooManyRetries = $monitor->assertRetryAllowed($scanId, 3);
        self::assertFalse($tooManyRetries['allowed']);
        self::assertSame(SafetyMonitor::DENY_RETRIES, $tooManyRetries['reason']);
        self::assertSame(1, $this->scanEvents(1, $scanId, 'retries_exceeded'));
        self::assertSame(15, $monitor->requestTimeoutSeconds($scanId));
    }

    // ---------------------------------------------------------------
    // AC-001 — nothing crosses the tenant boundary
    // ---------------------------------------------------------------

    public function test_cross_tenant_scan_invisible(): void
    {
        $this->seedTenant(1);
        $this->seedTenant(2);

        $ownerScans = $this->scans(1);
        $ownerScanId = $this->runningScan(1, $ownerScans);

        $otherScans = $this->scans(2);
        $otherScanId = $this->runningScan(2, $otherScans);
        self::assertNotSame($ownerScanId, $otherScanId);

        // Tenant 2 cannot even see tenant 1's scan ...
        self::assertNull($otherScans->findById($ownerScanId));

        // ... and therefore cannot stop it. The attempt is a no-op, not an
        // error that would confirm the row exists.
        $intruder = $this->killSwitch(2, $otherScans);
        self::assertFalse($intruder->requestStop($ownerScanId));
        self::assertFalse($intruder->isStopRequested($ownerScanId));

        // Tenant 1's scan is untouched and still running.
        self::assertFalse($ownerScans->isKillRequested($ownerScanId));
        self::assertSame('running', $ownerScans->requireById($ownerScanId)->status());
        self::assertFalse($this->monitor(1, $ownerScans, $this->profiles(1))->shouldStop($ownerScanId));

        // The monitor fails CLOSED for an invisible scan: it refuses rather
        // than allowing a request it cannot judge.
        $otherMonitor = $this->monitor(2, $otherScans, $this->profiles(2));
        $verdict = $otherMonitor->assertRequestAllowed($ownerScanId);
        self::assertFalse($verdict['allowed']);
        self::assertSame(SafetyMonitor::DENY_UNKNOWN_SCAN, $verdict['reason']);
        self::assertTrue($otherMonitor->shouldStop($ownerScanId));

        // The refusals are recorded against the tenant that attempted them,
        // and tenant 1's trail carries nothing about them.
        self::assertSame(1, $this->auditEvents(2, 'secscan.kill.requested'));
        self::assertSame(0, $this->auditEvents(1, 'secscan.kill.requested'));
        self::assertSame(1, $this->auditEvents(2, 'secscan.safety.deny'));
        self::assertSame(0, $this->auditEvents(1, 'secscan.safety.deny'));
        self::assertSame(0, $this->scanEvents(1, $ownerScanId, 'kill_switch'));
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private function profiles(int $tenantId): ScanProfileRepository
    {
        return new ScanProfileRepository($this->pdo, $tenantId, new AuditLogger($this->pdo));
    }

    private function scans(int $tenantId): ScanRepository
    {
        return new ScanRepository($this->pdo, $tenantId);
    }

    private function monitor(int $tenantId, ScanRepository $scans, ScanProfileRepository $profiles): SafetyMonitor
    {
        return new SafetyMonitor($scans, $profiles, $tenantId, new AuditLogger($this->pdo));
    }

    private function killSwitch(int $tenantId, ScanRepository $scans): KillSwitch
    {
        return new KillSwitch($scans, new AuditLogger($this->pdo), $tenantId);
    }

    private function scheduler(int $tenantId, ScanRepository $scans): ScanScheduler
    {
        return new ScanScheduler($scans, new AuditLogger($this->pdo), $tenantId);
    }

    /**
     * A started scan on a default (non-destructive) profile.
     */
    private function runningScan(int $tenantId, ScanRepository $scans): int
    {
        $authorizationId = $this->authorization($tenantId);
        $profileId = $this->profiles($tenantId)->create($authorizationId, ['http-headers']);
        $scanId = $scans->schedule($authorizationId, $profileId, 1);
        $scans->start($scanId);

        return $scanId;
    }

    /**
     * A recorded authorization for the profile to hang off (P3-T1 owns its
     * lifecycle; here it only has to exist and belong to this tenant).
     */
    private function authorization(int $tenantId): int
    {
        return (new AuthorizationRepository($this->pdo, $tenantId))->create(
            clientName: 'Acme Manufacturing Ltd',
            techniqueProfile: ['passive-recon', 'authenticated-web-scan'],
            stopContact: 'soc@acme.test',
            ownershipProofType: 'dns-txt',
            ownershipProofRef: 'dns TXT aiwebscapes-verify at acme.test',
            validFrom: new DateTimeImmutable('2026-01-01 00:00:00'),
            validTo: new DateTimeImmutable('2026-12-31 23:59:59')
        );
    }

    private function seedTenant(int $tenantId): void
    {
        $statement = $this->pdo->prepare(
            'INSERT IGNORE INTO tenants (id, slug, name, status, deployment_model)'
            . " VALUES (:id, :slug, :name, 'active', 'cloud')"
        );
        $statement->bindValue('id', $tenantId, PDO::PARAM_INT);
        $statement->bindValue('slug', 'safety-tenant-' . $tenantId);
        $statement->bindValue('name', 'Safety Monitor Tenant ' . $tenantId);
        $statement->execute();
    }

    /**
     * Counts scan_events of one type, read with the tenant bound - so a row
     * written under another tenant simply is not seen here.
     */
    private function scanEvents(int $tenantId, int $scanId, string $eventType): int
    {
        $statement = $this->pdo->prepare(
            'SELECT COUNT(*) FROM scan_events WHERE ' . TenantScope::COLUMN . ' = :' . TenantScope::PARAM
            . ' AND scan_id = :scan_id AND event_type = :event_type'
        );
        (new TenantScope($tenantId))->bindTo($statement);
        $statement->bindValue('scan_id', $scanId, PDO::PARAM_INT);
        $statement->bindValue('event_type', $eventType);
        $statement->execute();

        return (int) $statement->fetchColumn();
    }

    private function auditEvents(int $tenantId, string $action): int
    {
        $statement = $this->pdo->prepare(
            'SELECT COUNT(*) FROM audit_events WHERE ' . TenantScope::COLUMN . ' = :' . TenantScope::PARAM
            . ' AND action = :action'
        );
        (new TenantScope($tenantId))->bindTo($statement);
        $statement->bindValue('action', $action);
        $statement->execute();

        return (int) $statement->fetchColumn();
    }
}
