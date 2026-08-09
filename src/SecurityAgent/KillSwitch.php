<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Audit\AuditLogger;
use App\Tenancy\TenantScope;
use InvalidArgumentException;

/**
 * The operator kill switch (SFR-SAFE-002, and the P3 exit-gate acceptance test
 * "kill switch -> active jobs stop within defined operational threshold").
 *
 * WHAT "IMMEDIATE" MEANS HERE
 * ---------------------------
 * requestStop() sets a flag on the scan row and records the act. It sends no
 * signal, kills no process and closes no socket - the loop performing the scan
 * polls SafetyMonitor::shouldStop() (or isStopRequested() here) between
 * requests and stops itself. The operational threshold is therefore one
 * request, and it is met by a synchronous database read rather than by a
 * delivery that could be lost, queued behind a busy worker, or land on a host
 * that has been replaced.
 *
 * WHY THIS IS A SEPARATE CLASS FROM SafetyMonitor
 * -----------------------------------------------
 * They answer different questions for different callers. The monitor is asked
 * "may this request proceed?" thousands of times by the scanner; the kill
 * switch is asked "stop" once, by a human. Keeping the human-facing entry
 * point small and separately auditable means the operator action has its own
 * name in the trail ('secscan.kill.requested'), rather than being one branch
 * inside a hot path.
 *
 * DECIDES AND RECORDS, NEVER ACTS. Same split as ScopeManager and ToolGateway.
 *
 * © AI WebScapes 2026
 */
final class KillSwitch
{
    public const AUDIT_REQUESTED = 'secscan.kill.requested';

    public const AUDIT_CANCELLED = 'secscan.kill.cancelled';

    private const AUDIT_SOURCE = 'kill_switch';

    private const AUDIT_OBJECT_TYPE = 'security_scan';

    private int $tenantId;

    public function __construct(
        private readonly ScanRepository $scans,
        private readonly AuditLogger $audit,
        ?int $tenantId,
    ) {
        // Throws for null / 0 / negative: an unscoped kill switch is not a
        // representable state (AC-001).
        $this->tenantId = (new TenantScope($tenantId))->id();

        if ($this->scans->tenantId() !== $this->tenantId) {
            throw new InvalidArgumentException(sprintf(
                'KillSwitch is scoped to tenant %d but was given a repository scoped to tenant %d.',
                $this->tenantId,
                $this->scans->tenantId()
            ));
        }
    }

    /**
     * Requests an immediate stop.
     *
     * Returns false when the scan is not visible in this tenant - the attempt
     * is a no-op rather than an error, because an error that distinguished
     * "exists but forbidden" from "does not exist" would be an enumeration
     * oracle for other tenants' scan ids (AC-001).
     *
     * The audit row is written either way, against the tenant that ASKED, so a
     * cross-tenant attempt leaves a trail without touching the owner's.
     */
    public function requestStop(int $scanId, ?int $operatorUserId = null, string $reason = 'operator stop'): bool
    {
        $stopped = $this->scans->requestKill($scanId);

        if ($stopped) {
            // Evidence on the scan itself, so the run's own trail explains why
            // it ended (P3 acceptance test looks for this event).
            $this->scans->recordEvent($scanId, SafetyMonitor::DENY_KILL, $reason);
        }

        $this->audit->record(
            $this->tenantId,
            $operatorUserId,
            self::AUDIT_REQUESTED,
            self::AUDIT_OBJECT_TYPE,
            (string) $scanId,
            // audit_events.outcome is ENUM('success','failure','denied').
            $stopped ? 'success' : 'denied',
            self::AUDIT_SOURCE,
            null,
            [],
            [],
            $stopped ? $reason : 'scan not found in this tenant'
        );

        return $stopped;
    }

    /**
     * The synchronous poll. Cheap on purpose: it is called between requests.
     */
    public function isStopRequested(int $scanId): bool
    {
        return $this->scans->isKillRequested($scanId);
    }

    /**
     * Withdraws a stop request, which only makes sense while the scan is still
     * running: once the stop has taken effect, clearing the flag must not
     * bring the scan back to life. The repository enforces that condition, and
     * a refused cancellation returns false rather than throwing.
     */
    public function cancelStop(int $scanId, ?int $operatorUserId = null): bool
    {
        $cancelled = $this->scans->cancelKill($scanId);

        if ($cancelled) {
            $this->audit->record(
                $this->tenantId,
                $operatorUserId,
                self::AUDIT_CANCELLED,
                self::AUDIT_OBJECT_TYPE,
                (string) $scanId,
                'success',
                self::AUDIT_SOURCE,
                null,
                [],
                [],
                'kill request withdrawn while the scan was still running'
            );
        }

        return $cancelled;
    }
}
