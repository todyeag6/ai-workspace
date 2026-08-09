<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Data\TenantRepository;
use DateTimeImmutable;
use DateTimeZone;
use PDO;
use RuntimeException;

/**
 * Tenant-scoped persistence for scan runs and their live safety counters
 * (SFR-SAFE-001/002, SBR-3.5).
 *
 * WHY THE COUNTERS ARE IN THE DATABASE
 * ------------------------------------
 * The operator pulling the kill switch is not in the same process as the
 * scanner holding the socket, and a worker that restarts mid-scan must not
 * silently re-grant a whole minute's request allowance. Both facts rule out
 * in-memory counters, so observed_requests / active_concurrency / kill_requested
 * live on the row and every participant reads the same truth.
 *
 * WHY recordRequest() IS A COMPARE-AND-SWAP
 * -----------------------------------------
 * Two workers incrementing the same counter with read-then-write would lose an
 * increment, and a lost increment is a request the client never approved
 * (SFR-SAFE-001, and the P3 acceptance test "observed requests do not exceed
 * approved profile"). The UPDATE therefore carries the value it expects to
 * replace; a worker that loses the race sees rowCount() 0 and retries against
 * the new value. This uses only the scoped UPDATE the base class provides, so
 * the tenant predicate is still impossible to omit.
 *
 * WHY TIMESTAMPS ARE WRITTEN FROM PHP IN UTC AND NOT BY CURRENT_TIMESTAMP
 * ----------------------------------------------------------------------
 * The rate window and the duration ceiling are both subtractions between a
 * stored timestamp and "now". If the stored value came from the database
 * session's clock and "now" came from PHP's, the two could sit in different
 * zones and the difference would be hours out - which in one direction stops a
 * perfectly healthy scan. Every timestamp this class writes is a UTC string
 * from the injected clock, and SecurityScan parses them back as UTC.
 *
 * DECIDES NOTHING. This class moves rows. Whether a request is permissible is
 * SafetyMonitor's judgement, and the split is deliberate: the component that
 * counts must not also be the component that forgives.
 *
 * © AI WebScapes 2026
 */
final class ScanRepository extends TenantRepository
{
    /** SFR-SAFE-001 rate limits are per minute, so the fixed window is 60s. */
    public const RATE_WINDOW_SECONDS = 60;

    /** Bounded so a pathological contention loop terminates rather than spins. */
    private const CAS_ATTEMPTS = 5;

    private const TIMESTAMP_FORMAT = 'Y-m-d H:i:s';

    private ScanEventRepository $events;

    public function __construct(PDO $pdo, ?int $tenantId)
    {
        parent::__construct($pdo, $tenantId);

        // Built here rather than injected so a caller cannot hand in an event
        // repository scoped to a different tenant.
        $this->events = new ScanEventRepository($pdo, $tenantId);
    }

    protected function table(): string
    {
        return 'security_scans';
    }

    /**
     * @return list<string>
     */
    protected function columns(): array
    {
        return [
            'id',
            'tenant_id',
            'authorization_id',
            'scan_profile_id',
            'profile_version',
            'status',
            'kill_requested',
            'observed_requests',
            'active_concurrency',
            'rate_window_start',
            'started_at',
            'stopped_at',
            'scheduled_at',
        ];
    }

    /**
     * Records a scheduled run. profile_version is copied onto the run so the
     * envelope it was granted stays legible after the profile moves on.
     */
    public function schedule(int $authorizationId, int $profileId, int $profileVersion): int
    {
        return (int) $this->insertScoped([
            'authorization_id' => $authorizationId,
            'scan_profile_id' => $profileId,
            'profile_version' => $profileVersion,
            'status' => SecurityScan::STATUS_SCHEDULED,
            'kill_requested' => 0,
            'observed_requests' => 0,
            'active_concurrency' => 0,
        ]);
    }

    /**
     * Starts the run and opens the first rate window.
     *
     * A scan that is already stopped or killed is NOT restarted: reviving it
     * here would be a way to walk around the kill switch (SFR-SAFE-002).
     */
    public function start(int $id, ?DateTimeImmutable $now = null): bool
    {
        $stamp = $this->stamp($now);

        return $this->updateScoped(
            [
                'status' => SecurityScan::STATUS_RUNNING,
                'started_at' => $stamp,
                'rate_window_start' => $stamp,
                'observed_requests' => 0,
            ],
            "id = :id AND kill_requested = 0 AND status IN ('scheduled', 'paused')",
            ['id' => $id]
        ) > 0;
    }

    /**
     * The number of requests already observed in the CURRENT window, rolling
     * the window over first when the old one has expired.
     *
     * Separate from recordRequest() on purpose. SafetyMonitor has to be able
     * to ask "would this request breach the limit?" and refuse WITHOUT
     * counting it - the acceptance criterion is about observed requests not
     * exceeding the approved profile, so a refused request must not be added
     * to the tally it was refused for.
     */
    public function windowCount(int $id, ?DateTimeImmutable $now = null): int
    {
        $scan = $this->findById($id);
        if ($scan === null) {
            return 0;
        }

        $moment = $now ?? $this->clock();
        $windowStart = $scan->rateWindowStart();
        $windowExpired = $windowStart === null
            || $moment->getTimestamp() - $windowStart->getTimestamp() >= self::RATE_WINDOW_SECONDS;

        if ($windowExpired) {
            $this->updateScoped(
                [
                    'observed_requests' => 0,
                    'rate_window_start' => $moment->format(self::TIMESTAMP_FORMAT),
                ],
                'id = :id',
                ['id' => $id]
            );

            return 0;
        }

        return $scan->observedRequests();
    }

    /**
     * Counts one issued request and returns the new in-window total.
     *
     * @throws RuntimeException When the counter could not be advanced without losing an increment.
     */
    public function recordRequest(int $id, ?DateTimeImmutable $now = null): int
    {
        $moment = $now ?? $this->clock();

        for ($attempt = 0; $attempt < self::CAS_ATTEMPTS; $attempt++) {
            $current = $this->windowCount($id, $moment);

            $affected = $this->updateScoped(
                ['observed_requests' => $current + 1],
                'id = :id AND observed_requests = :expected',
                ['id' => $id, 'expected' => $current]
            );

            if ($affected > 0) {
                return $current + 1;
            }

            // The row is either gone / another tenant's (0 rows forever), or a
            // concurrent worker moved the counter. Distinguish them so an
            // invisible scan does not spin the loop.
            if ($this->findById($id) === null) {
                return 0;
            }
        }

        throw new RuntimeException(sprintf(
            'Could not advance the request counter for scan %d after %d attempts.',
            $id,
            self::CAS_ATTEMPTS
        ));
    }

    /**
     * Adjusts the in-flight worker count and returns the new value.
     *
     * Clamped at zero: active_concurrency is UNSIGNED, and a stray decrement
     * must not abort the scan with a database error.
     */
    public function recordConcurrency(int $id, int $delta): int
    {
        $scan = $this->findById($id);
        if ($scan === null) {
            return 0;
        }

        $next = max(0, $scan->activeConcurrency() + $delta);
        $this->updateScoped(['active_concurrency' => $next], 'id = :id', ['id' => $id]);

        return $next;
    }

    /**
     * SBR-3.5: a pause is what target instability produces - the run is halted
     * but not written off, so an operator can resume it once the target
     * recovers.
     */
    public function pause(int $id): bool
    {
        return $this->transitionTo(SecurityScan::STATUS_PAUSED, $id, "status = 'running'");
    }

    /**
     * The terminal safety stop (SFR-SAFE-002, SBR-3.5). Reachable from any
     * non-terminal status, because a stop must never be blocked by the state
     * the scan happens to be in.
     */
    public function stop(int $id, ?DateTimeImmutable $now = null): bool
    {
        return $this->updateScoped(
            [
                'status' => SecurityScan::STATUS_STOPPED,
                'stopped_at' => $this->stamp($now),
            ],
            "id = :id AND status IN ('scheduled', 'running', 'paused')",
            ['id' => $id]
        ) > 0;
    }

    public function complete(int $id, ?DateTimeImmutable $now = null): bool
    {
        return $this->updateScoped(
            [
                'status' => SecurityScan::STATUS_COMPLETED,
                'stopped_at' => $this->stamp($now),
            ],
            "id = :id AND status = 'running'",
            ['id' => $id]
        ) > 0;
    }

    public function fail(int $id, ?DateTimeImmutable $now = null): bool
    {
        return $this->updateScoped(
            [
                'status' => SecurityScan::STATUS_FAILED,
                'stopped_at' => $this->stamp($now),
            ],
            "id = :id AND status IN ('scheduled', 'running', 'paused')",
            ['id' => $id]
        ) > 0;
    }

    /**
     * The operator kill switch (SFR-SAFE-002).
     *
     * Sets a FLAG rather than a status: the request must be visible to the
     * next poll of the loop holding the socket without waiting for a
     * transition only the scanner itself can make. Returns false when the scan
     * is not visible in this tenant, which is how a cross-tenant stop attempt
     * becomes a no-op rather than an error that would confirm the row exists.
     */
    public function requestKill(int $id): bool
    {
        return $this->updateScoped(['kill_requested' => 1], 'id = :id', ['id' => $id]) > 0;
    }

    /**
     * Withdraws a kill request, but only while the scan is still running: once
     * the stop has taken effect, un-setting the flag must not resurrect it.
     */
    public function cancelKill(int $id): bool
    {
        return $this->updateScoped(
            ['kill_requested' => 0],
            "id = :id AND status = 'running'",
            ['id' => $id]
        ) > 0;
    }

    public function isKillRequested(int $id): bool
    {
        return $this->findById($id)?->isKillRequested() ?? false;
    }

    /**
     * Records a safety event, but ONLY for a scan visible in this tenant.
     *
     * The visibility check is the point: without it a caller could attach an
     * event carrying our tenant_id to another tenant's scan_id, which is the
     * cross-tenant confusion AC-001 forbids. Returns 0 when there is nothing
     * to record against.
     */
    public function recordEvent(int $scanId, string $eventType, ?string $detail = null): int
    {
        if ($this->findById($scanId) === null) {
            return 0;
        }

        return $this->events->add($scanId, $eventType, $detail);
    }

    /**
     * The recorded safety trail for one scan.
     *
     * @return list<array<string, scalar|null>>
     */
    public function eventsFor(int $scanId): array
    {
        return $this->events->forScan($scanId);
    }

    public function countEvents(int $scanId, string $eventType): int
    {
        return $this->events->countOfType($scanId, $eventType);
    }

    /**
     * Null both when the scan does not exist and when it belongs to another
     * tenant - deliberately indistinguishable (AC-001).
     */
    public function findById(int $id): ?SecurityScan
    {
        $rows = $this->selectScoped('id = :id', ['id' => $id]);
        if ($rows === []) {
            return null;
        }

        return SecurityScan::fromRow($rows[0]);
    }

    /**
     * @throws RuntimeException When no such scan exists in this tenant.
     */
    public function requireById(int $id): SecurityScan
    {
        $scan = $this->findById($id);
        if ($scan === null) {
            throw new RuntimeException(sprintf(
                'Security scan %d does not exist for tenant %d.',
                $id,
                $this->tenantId()
            ));
        }

        return $scan;
    }

    private function transitionTo(string $status, int $id, string $from): bool
    {
        return $this->updateScoped(['status' => $status], 'id = :id AND (' . $from . ')', ['id' => $id]) > 0;
    }

    private function stamp(?DateTimeImmutable $now): string
    {
        return ($now ?? $this->clock())->format(self::TIMESTAMP_FORMAT);
    }

    /**
     * The default clock, in UTC. Callers that need determinism inject $now
     * instead - no method here reads the clock when it was given one.
     */
    private function clock(): DateTimeImmutable
    {
        return new DateTimeImmutable('now', new DateTimeZone('UTC'));
    }
}
