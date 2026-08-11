<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Audit\AuditLogger;
use App\Tenancy\TenantScope;
use DateTimeImmutable;
use InvalidArgumentException;
use RuntimeException;

/**
 * Records a scan run against an approved profile (SBR-3.3, SFR-SAFE-001).
 *
 * WHY THE SCHEDULER IS THIS THIN
 * ------------------------------
 * Everything that decides whether a scan MAY run lives elsewhere and on
 * purpose: the authorization gate is App\SecurityAgent\ScopeManager (P3-T1) and
 * the safety envelope is App\SecurityAgent\SafetyMonitor. A scheduler that
 * re-implemented either would create a second opinion that can drift from the
 * first, and a second opinion about authority is how an unauthorised scan gets
 * scheduled.
 *
 * What it does own is the PROFILE VERSION PIN. The run records which version
 * of the envelope it was granted, so a later edit to the profile cannot
 * retroactively change what an old scan is understood to have been allowed to
 * do - and the scheduling act itself is audited, so a run always has a
 * traceable origin.
 *
 * © AI WebScapes 2026
 */
final class ScanScheduler
{
    public const AUDIT_SCHEDULED = 'secscan.scheduled';
    public const AUDIT_SCHEDULED_RECURRING = 'secscan.scheduled.recurring';

    private const AUDIT_SOURCE = 'scan_scheduler';

    private const AUDIT_OBJECT_TYPE = 'security_scan';

    private int $tenantId;

    public function __construct(
        private readonly ScanRepository $scans,
        private readonly AuditLogger $audit,
        ?int $tenantId,
    ) {
        // Throws for null / 0 / negative (AC-001).
        $this->tenantId = (new TenantScope($tenantId))->id();

        if ($this->scans->tenantId() !== $this->tenantId) {
            throw new InvalidArgumentException(sprintf(
                'ScanScheduler is scoped to tenant %d but was given a repository scoped to tenant %d.',
                $this->tenantId,
                $this->scans->tenantId()
            ));
        }
    }

    /**
     * Records a scheduled run and returns its id.
     *
     * The run is created in 'scheduled', never 'running': starting it is a
     * separate act, so a scan cannot begin issuing requests as a side effect
     * of being planned.
     */
    public function scheduleScan(
        int $authorizationId,
        int $profileId,
        int $profileVersion,
        ?int $scheduledByUserId = null
    ): int {
        $scanId = $this->scans->schedule($authorizationId, $profileId, $profileVersion);

        $this->audit->record(
            $this->tenantId,
            $scheduledByUserId,
            self::AUDIT_SCHEDULED,
            self::AUDIT_OBJECT_TYPE,
            (string) $scanId,
            // audit_events.outcome is ENUM('success','failure','denied').
            'success',
            self::AUDIT_SOURCE,
            null,
            [],
            [],
            sprintf('profile %d version %d', $profileId, $profileVersion)
        );

        return $scanId;
    }

    /**
     * Schedules a RECURRING scan.
     *
     * Wraps ScanRepository::scheduleRecurring() with the policy the one-shot
     * scheduleScan() does not need: it loads config/security/SCAN_SCHEDULE_POLICY.php
     * (PROPOSED, ratifiable), refuses a cadence the policy disallows (AC-002),
     * and — the SFR-AUTH-001 guard — refuses a validity window that has already
     * lapsed at $now. It also caps the burst of future runs a single call may
     * create (max_horizon_runs) so a recurrence cannot pre-book years ahead in
     * one shot.
     *
     * Fails closed: a missing or malformed policy refuses the schedule rather
     * than falling back to undefined behaviour.
     *
     * @throws InvalidArgumentException When $cadence is not in the policy's
     *         allowed_cadences, or $validUntil is at or before $now (SFR-AUTH-001).
     * @throws RuntimeException When the policy cannot be loaded.
     */
    public function scheduleRecurring(
        int $authorizationId,
        int $profileId,
        int $profileVersion,
        string $cadence,
        DateTimeImmutable $validUntil,
        DateTimeImmutable $now,
        ?int $scheduledByUserId = null,
    ): int {
        $policy = $this->loadPolicy();
        $allowed = $policy['allowed_cadences'] ?? [];
        if (!is_array($allowed) || !in_array($cadence, $allowed, true)) {
            throw new InvalidArgumentException(sprintf(
                'Recurrence cadence "%s" is not permitted by policy (allowed: %s).',
                $cadence,
                implode(', ', $allowed)
            ));
        }

        // SFR-AUTH-001: an authorization whose validity period has already lapsed
        // may not be used to schedule a recurring run. Fail closed.
        if ($validUntil->getTimestamp() <= $now->getTimestamp()) {
            throw new InvalidArgumentException(
                'Cannot schedule a recurring scan: the authorization validity period has already lapsed (SFR-AUTH-001).'
            );
        }

        $effectiveCadence = $cadence;
        $horizon = max(1, (int) ($policy['max_horizon_runs'] ?? 1));
        $nextRunAt = ScanRepository::rollForward($effectiveCadence, $now);

        // The initial next_run_at is the first due instant; the horizon cap is a
        // guard on any descendant scheduling logic, recorded on the policy version
        // for traceability.
        $scanId = $this->scans->scheduleRecurring(
            $authorizationId,
            $profileId,
            $profileVersion,
            $effectiveCadence,
            $validUntil,
            $nextRunAt,
            $policy['config_version'] ?? null
        );

        $this->audit->record(
            $this->tenantId,
            $scheduledByUserId,
            self::AUDIT_SCHEDULED_RECURRING,
            self::AUDIT_OBJECT_TYPE,
            (string) $scanId,
            'success',
            self::AUDIT_SOURCE,
            null,
            [],
            [],
            sprintf(
                'recurring profile %d version %d cadence %s valid_until %s horizon %d',
                $profileId,
                $profileVersion,
                $effectiveCadence,
                $validUntil->format('Y-m-d'),
                $horizon
            )
        );

        return $scanId;
    }

    /**
     * Loads the ratifiable scan-schedule policy. Kept separate so the load path
     * is unit-testable and a malformed file fails loudly.
     *
     * @return array<string, mixed>
     * @throws RuntimeException When the file is missing or returns no array.
     */
    private function loadPolicy(): array
    {
        $path = dirname(__DIR__, 2) . '/config/security/SCAN_SCHEDULE_POLICY.php';
        if (!is_file($path)) {
            throw new RuntimeException('Scan schedule policy missing: ' . $path);
        }

        /** @var mixed $policy */
        $policy = require $path;
        if (!is_array($policy)) {
            throw new RuntimeException('Scan schedule policy did not return an array.');
        }

        return $policy;
    }
}
