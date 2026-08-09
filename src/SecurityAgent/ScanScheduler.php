<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Audit\AuditLogger;
use App\Tenancy\TenantScope;
use InvalidArgumentException;

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
}
