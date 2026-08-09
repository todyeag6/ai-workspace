<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Audit\AuditLogger;
use App\Tenancy\TenantScope;
use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;

/**
 * The safety envelope, enforced (SFR-SAFE-001/002/003, SBR-3.3/3.5, and the P3
 * exit-gate acceptance tests "kill switch -> active jobs stop", "rate limit ->
 * observed requests do not exceed approved profile" and "target instability ->
 * safety monitor stops or pauses scan and alerts").
 *
 * WHAT THIS CLASS DOES AND DELIBERATELY DOES NOT DO
 * -------------------------------------------------
 * It DECIDES. It opens no socket, cancels no request and kills no process -
 * the same split App\SecurityAgent\ScopeManager and App\Tools\ToolGateway
 * make, and for the same reason: the component that judges must not be the
 * component that can be talked into acting. assertRequestAllowed() returns a
 * verdict and shouldStop() returns a flag; the loop that holds the connection
 * is what stops. That separation is load-bearing - merged, a bug in the
 * network layer becomes a bug in the safety layer.
 *
 * PER REQUEST, NOT PER SCAN
 * -------------------------
 * SFR-SAFE-001 says every scan enforces its limits, and a limit checked once
 * at start-up is not enforced - it is merely recorded. The scanner calls
 * assertRequestAllowed() BEFORE each request and polls shouldStop() each tick,
 * so a kill switch pulled mid-scan, a window that filled up, a target that
 * started failing or an authorization that expired are all seen within one
 * request of happening.
 *
 * WHY A REFUSED REQUEST IS NOT COUNTED
 * ------------------------------------
 * The acceptance criterion is that OBSERVED requests do not exceed the
 * approved profile. So the tally is read first, compared, and only incremented
 * once the request has actually been permitted. Counting first and refusing
 * afterwards would push observed_requests one past the limit the client
 * agreed to - the exact number the test looks at.
 *
 * ORDER OF CHECKS, AND WHY IT IS THIS ORDER
 * -----------------------------------------
 *   1. visibility - a scan this tenant cannot see is refused before anything
 *      else, and fails CLOSED (AC-001).
 *   2. kill switch - the operator's instruction outranks every other
 *      consideration (SFR-SAFE-002).
 *   3. lifecycle - a scan that is paused, stopped or finished issues nothing.
 *   4. destructive approval - SFR-SAFE-003, checked before any budget is
 *      spent, because "allowed but destructive" is the worst possible verdict.
 *   5. duration, then concurrency, then rate - cheapest terminal condition
 *      first: a scan past its agreed duration is STOPPED, not merely refused,
 *      so it must not be reported as a rate problem.
 *
 * EVERY REFUSAL IS RECORDED
 * -------------------------
 * Each denial writes a scan_events row before the verdict is returned, so
 * there is no path out of this class that refuses silently. A refusal that
 * cannot be attached to a scan (because the scan is not visible to this
 * tenant) is recorded as an audit event against the tenant that attempted it
 * instead - never against the tenant that owns the scan.
 *
 * © AI WebScapes 2026
 */
final class SafetyMonitor
{
    public const ALLOWED = 'allowed';

    public const DENY_UNKNOWN_SCAN = 'scan_not_found';

    public const DENY_KILL = 'kill_switch';

    public const DENY_NOT_RUNNING = 'scan_not_running';

    public const DENY_DESTRUCTIVE_UNAPPROVED = 'destructive_not_approved';

    public const DENY_DURATION = 'duration_exceeded';

    public const DENY_CONCURRENCY = 'concurrency_exceeded';

    public const DENY_RATE = 'rate_exceeded';

    public const DENY_PAYLOAD = 'payload_exceeded';

    public const DENY_RETRIES = 'retries_exceeded';

    public const EVENT_INSTABILITY = 'instability_pause';

    public const EVENT_AUTH_EXPIRED = 'auth_expired';

    public const EVENT_SCOPE_MISMATCH = 'scope_mismatch';

    public const AUDIT_DENY = 'secscan.safety.deny';

    public const AUDIT_INSTABILITY = 'secscan.instability.alert';

    private const AUDIT_SOURCE = 'safety_monitor';

    private const AUDIT_OBJECT_TYPE = 'security_scan';

    private int $tenantId;

    public function __construct(
        private readonly ScanRepository $scans,
        private readonly ScanProfileRepository $profiles,
        ?int $tenantId,
        private readonly AuditLogger $audit,
    ) {
        // Throws for null / 0 / negative: an unscoped safety monitor is not a
        // representable state (AC-001).
        $this->tenantId = (new TenantScope($tenantId))->id();

        $this->assertSameTenant($this->scans->tenantId(), 'scan');
        $this->assertSameTenant($this->profiles->tenantId(), 'scan profile');
    }

    /**
     * The per-request decision (SFR-SAFE-001). Called BEFORE each request.
     *
     * `count` is the number of requests observed in the current rate window
     * after this call: incremented when the request is permitted, unchanged
     * when it is refused.
     *
     * @param  DateTimeImmutable|null $now Injected for determinism; defaults to the UTC clock.
     * @return array{allowed: bool, reason: string, count: int}
     */
    public function assertRequestAllowed(int $scanId, ?DateTimeImmutable $now = null): array
    {
        $moment = $now ?? $this->clock();

        $scan = $this->scans->findById($scanId);
        if ($scan === null) {
            // Fails closed, and is evidenced against the tenant that asked -
            // there is no scan of ours to attach an event to.
            return $this->denyUnknown($scanId);
        }

        $profile = $this->profiles->findById($scan->profileId());
        if ($profile === null) {
            return $this->deny($scanId, self::DENY_UNKNOWN_SCAN, $scan->observedRequests(), 'profile missing');
        }

        // (2) SFR-SAFE-002: the operator's instruction outranks everything.
        if ($scan->isKillRequested()) {
            return $this->deny($scanId, self::DENY_KILL, $scan->observedRequests(), 'kill switch engaged');
        }

        // (3) A paused or stopped scan issues nothing.
        if (!$scan->isRunning()) {
            return $this->deny(
                $scanId,
                self::DENY_NOT_RUNNING,
                $scan->observedRequests(),
                'scan status ' . $scan->status()
            );
        }

        // (4) SFR-SAFE-003: enabled is not approved.
        if ($profile->isDestructiveEnabled() && !$profile->isDestructiveApproved()) {
            return $this->deny(
                $scanId,
                self::DENY_DESTRUCTIVE_UNAPPROVED,
                $scan->observedRequests(),
                'destructive checks are not separately approved'
            );
        }

        // (5) Duration is terminal: past the agreed window the scan STOPS.
        $elapsed = $scan->elapsedSeconds($moment);
        if ($elapsed !== null && $elapsed > $profile->maxDurationSec()) {
            $this->scans->stop($scanId, $moment);

            return $this->deny(
                $scanId,
                self::DENY_DURATION,
                $scan->observedRequests(),
                sprintf('elapsed %d seconds exceeds the agreed %d', $elapsed, $profile->maxDurationSec())
            );
        }

        if ($scan->activeConcurrency() > $profile->concurrencyLimit()) {
            return $this->deny(
                $scanId,
                self::DENY_CONCURRENCY,
                $scan->observedRequests(),
                sprintf(
                    'in flight %d exceeds the agreed %d',
                    $scan->activeConcurrency(),
                    $profile->concurrencyLimit()
                )
            );
        }

        // Read the tally, compare, and only then count it - see the class
        // comment on why the order matters to the acceptance criterion.
        $observed = $this->scans->windowCount($scanId, $moment);
        if ($observed >= $profile->rateLimitPerMin()) {
            return $this->deny(
                $scanId,
                self::DENY_RATE,
                $observed,
                sprintf('observed %d in this window, agreed %d per minute', $observed, $profile->rateLimitPerMin())
            );
        }

        return [
            'allowed' => true,
            'reason' => self::ALLOWED,
            'count' => $this->scans->recordRequest($scanId, $moment),
        ];
    }

    /**
     * The flag the loop holding the socket polls each tick (SFR-SAFE-002).
     *
     * "Immediate" is implemented as a synchronous read rather than a signal or
     * a queued message: there is no delivery to fail and no worker to be busy.
     * A scan this tenant cannot see reads as "stop" - fail closed.
     */
    public function shouldStop(int $scanId): bool
    {
        return $this->scans->findById($scanId)?->shouldStop() ?? true;
    }

    /**
     * SBR-3.5 + the P3 exit-gate test "target instability -> safety monitor
     * stops or pauses scan and alerts".
     *
     * PAUSE, NOT STOP: instability is a property of the target, not a breach
     * by the operator, so the run is halted in a resumable state. Both
     * thresholds are passed in rather than read from configuration here, so
     * the decision stays pure and testable.
     *
     * `paused` reports what THIS observation did: false when the target looked
     * healthy, and false when the scan was no longer running to be paused.
     *
     * @return array{paused: bool, reason: string}
     */
    public function observeTargetInstability(
        int $scanId,
        float $errorRate,
        int $latencyMs,
        int $latencyThresholdMs,
        float $errorRateThreshold
    ): array {
        if ($this->scans->findById($scanId) === null) {
            $this->denyUnknown($scanId);

            return ['paused' => false, 'reason' => self::DENY_UNKNOWN_SCAN];
        }

        if ($errorRate < $errorRateThreshold && $latencyMs < $latencyThresholdMs) {
            return ['paused' => false, 'reason' => self::ALLOWED];
        }

        $detail = sprintf(
            'error rate %.2f of %.2f, latency %d ms of %d ms',
            $errorRate,
            $errorRateThreshold,
            $latencyMs,
            $latencyThresholdMs
        );

        // Halt first, then evidence: the acceptance test requires BOTH the
        // pause and the alert, and an alert nobody acted on is not a stop.
        $paused = $this->scans->pause($scanId);
        $this->scans->recordEvent($scanId, self::EVENT_INSTABILITY, $detail);

        // The alert. Recorded as an audit event rather than sent from here: a
        // monitor that delivers mail is a monitor that can be blocked by a
        // mail server, and the notification channel is a separate concern.
        $this->audit->record(
            $this->tenantId,
            null,
            self::AUDIT_INSTABILITY,
            self::AUDIT_OBJECT_TYPE,
            (string) $scanId,
            // audit_events.outcome is ENUM('success','failure','denied').
            // 'failure' rather than 'success': the row records that a TARGET
            // became unhealthy, so a query for safety incidents finds it.
            'failure',
            self::AUDIT_SOURCE,
            null,
            [],
            [],
            $detail
        );

        return ['paused' => $paused, 'reason' => self::EVENT_INSTABILITY];
    }

    /**
     * SBR-3.5: automatic stop on authorization expiry or scope mismatch.
     *
     * The two signals arrive as booleans rather than as an Authorization or a
     * ScopeManager verdict, so this class depends on neither: the caller
     * already holds those answers from P3-T1, and re-deriving them here would
     * duplicate the authority check in a second place that could drift.
     *
     * Expiry is reported ahead of scope: an engagement that has ended should
     * be recorded as ended, not as a scope detail.
     *
     * @return array{stopped: bool, reason: string}
     */
    public function autoStopOnSignals(int $scanId, bool $authorizationExpired, bool $scopeMismatch): array
    {
        if (!$authorizationExpired && !$scopeMismatch) {
            return ['stopped' => false, 'reason' => self::ALLOWED];
        }

        if ($this->scans->findById($scanId) === null) {
            $this->denyUnknown($scanId);

            return ['stopped' => false, 'reason' => self::DENY_UNKNOWN_SCAN];
        }

        $reason = $authorizationExpired ? self::EVENT_AUTH_EXPIRED : self::EVENT_SCOPE_MISMATCH;

        $stopped = $this->scans->stop($scanId);
        $this->scans->recordEvent(
            $scanId,
            $reason,
            $authorizationExpired
                ? 'authorization is no longer valid'
                : 'target is outside the agreed scope'
        );

        return ['stopped' => $stopped, 'reason' => $reason];
    }

    /**
     * SFR-SAFE-001, payload ceiling. Asked before a body is read or sent, so
     * an oversized payload is refused rather than truncated after the fact.
     *
     * @return array{allowed: bool, reason: string, bytes: int}
     */
    public function enforcePayloadSize(int $scanId, int $bytes): array
    {
        $profile = $this->profileForScan($scanId);
        if ($profile === null) {
            $this->denyUnknown($scanId);

            return ['allowed' => false, 'reason' => self::DENY_UNKNOWN_SCAN, 'bytes' => $bytes];
        }

        if ($bytes > $profile->maxPayloadBytes()) {
            $this->scans->recordEvent(
                $scanId,
                self::DENY_PAYLOAD,
                sprintf('payload %d bytes exceeds the agreed %d', $bytes, $profile->maxPayloadBytes())
            );

            return ['allowed' => false, 'reason' => self::DENY_PAYLOAD, 'bytes' => $bytes];
        }

        return ['allowed' => true, 'reason' => self::ALLOWED, 'bytes' => $bytes];
    }

    /**
     * SFR-SAFE-001, retry ceiling. $attempt is the retry number about to be
     * made (1 is the first retry), so a profile allowing 3 permits 1..3.
     *
     * Retries are a load multiplier on a target that is already failing, which
     * is why the limit is part of the safety envelope and not of the HTTP
     * client's configuration.
     *
     * @return array{allowed: bool, reason: string, attempt: int}
     */
    public function assertRetryAllowed(int $scanId, int $attempt): array
    {
        $profile = $this->profileForScan($scanId);
        if ($profile === null) {
            $this->denyUnknown($scanId);

            return ['allowed' => false, 'reason' => self::DENY_UNKNOWN_SCAN, 'attempt' => $attempt];
        }

        if ($attempt > $profile->maxRetries()) {
            $this->scans->recordEvent(
                $scanId,
                self::DENY_RETRIES,
                sprintf('retry %d exceeds the agreed %d', $attempt, $profile->maxRetries())
            );

            return ['allowed' => false, 'reason' => self::DENY_RETRIES, 'attempt' => $attempt];
        }

        return ['allowed' => true, 'reason' => self::ALLOWED, 'attempt' => $attempt];
    }

    /**
     * SFR-SAFE-001, per-request timeout. The monitor decides the value; the
     * component holding the socket is what applies it. Null when the scan is
     * not visible to this tenant, which the caller must treat as "do not
     * request at all" rather than as "no timeout".
     */
    public function requestTimeoutSeconds(int $scanId): ?int
    {
        return $this->profileForScan($scanId)?->requestTimeoutSec();
    }

    /**
     * The envelope a scan is running under, or null when either the scan or
     * its profile is not visible in this tenant.
     */
    public function profileForScan(int $scanId): ?ScanProfile
    {
        $scan = $this->scans->findById($scanId);
        if ($scan === null) {
            return null;
        }

        return $this->profiles->findById($scan->profileId());
    }

    /**
     * Records the refusal against the scan, then returns it. The write happens
     * first so a caller cannot receive a denial that was never evidenced.
     *
     * @return array{allowed: bool, reason: string, count: int}
     */
    private function deny(int $scanId, string $reason, int $count, string $detail): array
    {
        $this->scans->recordEvent($scanId, $reason, $detail);

        return ['allowed' => false, 'reason' => $reason, 'count' => $count];
    }

    /**
     * A refusal that cannot be attached to a scan, because the scan is not
     * visible to this tenant.
     *
     * Recorded as an audit event against the ASKING tenant. Writing a
     * scan_events row instead would either be impossible (the scan belongs to
     * someone else) or would leak the attempt into the owner's trail, and both
     * are AC-001 problems.
     *
     * @return array{allowed: bool, reason: string, count: int}
     */
    private function denyUnknown(int $scanId): array
    {
        $this->audit->record(
            $this->tenantId,
            null,
            self::AUDIT_DENY,
            self::AUDIT_OBJECT_TYPE,
            (string) $scanId,
            'denied',
            self::AUDIT_SOURCE,
            null,
            [],
            [],
            // Spaces, not underscores: AuditLogger redacts runs of 16+ word
            // characters as possible secrets, which would eat the reason.
            'scan not found in this tenant'
        );

        return ['allowed' => false, 'reason' => self::DENY_UNKNOWN_SCAN, 'count' => 0];
    }

    private function assertSameTenant(int $collaboratorTenantId, string $what): void
    {
        if ($collaboratorTenantId !== $this->tenantId) {
            throw new InvalidArgumentException(sprintf(
                'SafetyMonitor is scoped to tenant %d but was given a %s repository scoped to tenant %d.',
                $this->tenantId,
                $what,
                $collaboratorTenantId
            ));
        }
    }

    private function clock(): DateTimeImmutable
    {
        return new DateTimeImmutable('now', new DateTimeZone('UTC'));
    }
}
