<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Tenancy\TenantScope;
use DateTimeImmutable;
use DateTimeZone;
use Exception;
use InvalidArgumentException;

/**
 * One scan run and its live safety counters (SFR-SAFE-001/002, SBR-3.5) - an
 * immutable snapshot, never a live handle.
 *
 * WHY shouldStop() LIVES HERE AS WELL AS ON SafetyMonitor
 * ------------------------------------------------------
 * SFR-SAFE-002 says the kill switch is IMMEDIATE. In practice that means the
 * loop holding the socket polls a flag between requests, and the poll has to
 * be a cheap synchronous read - not a message, not a queue, not a callback.
 * shouldStop() is that read, expressed on the snapshot the scanner already
 * has; SafetyMonitor::shouldStop() is the same question re-asked against the
 * database for a caller that has no snapshot.
 *
 * WHY THE TIMESTAMPS ARE READ AS UTC
 * ----------------------------------
 * The duration ceiling (SFR-SAFE-001) is a subtraction, and a subtraction
 * between two clocks in different zones silently produces hours of error - in
 * the dangerous direction it would stop a healthy scan. Every timestamp this
 * class parses is interpreted in UTC, and ScanRepository writes them in UTC,
 * so the pair is consistent regardless of the database session's zone.
 *
 * © AI WebScapes 2026
 */
final class SecurityScan
{
    public const STATUS_SCHEDULED = 'scheduled';

    public const STATUS_RUNNING = 'running';

    public const STATUS_PAUSED = 'paused';

    public const STATUS_STOPPED = 'stopped';

    public const STATUS_COMPLETED = 'completed';

    public const STATUS_FAILED = 'failed';

    public function __construct(
        private readonly int $tenantId,
        private readonly int $id,
        private readonly int $authorizationId,
        private readonly int $profileId,
        private readonly int $profileVersion,
        private readonly string $status,
        private readonly bool $killRequested,
        private readonly int $observedRequests,
        private readonly int $activeConcurrency,
        private readonly ?DateTimeImmutable $rateWindowStart = null,
        private readonly ?DateTimeImmutable $startedAt = null,
        private readonly ?DateTimeImmutable $stoppedAt = null,
        private readonly string $recurrence = 'none',
        private readonly ?DateTimeImmutable $validUntil = null,
        private readonly ?DateTimeImmutable $nextRunAt = null,
        private readonly ?string $recurrencePolicyVersion = null,
    ) {
    }

    /**
     * @param array<string, scalar|null> $row
     */
    public static function fromRow(array $row): self
    {
        // Throws UnscopedQueryException for null / 0 / negative (AC-001).
        $tenant = new TenantScope(self::intOrNull($row['tenant_id'] ?? null));

        $id = self::intOrNull($row['id'] ?? null);
        if ($id === null || $id <= 0) {
            throw new InvalidArgumentException('A security scan row must carry a positive id.');
        }

        return new self(
            $tenant->id(),
            $id,
            self::intOf($row['authorization_id'] ?? null),
            self::intOf($row['scan_profile_id'] ?? null),
            self::intOf($row['profile_version'] ?? null),
            self::stringOf($row['status'] ?? null),
            self::boolOf($row['kill_requested'] ?? null),
            self::intOf($row['observed_requests'] ?? null),
            self::intOf($row['active_concurrency'] ?? null),
            self::timeOrNull($row['rate_window_start'] ?? null),
            self::timeOrNull($row['started_at'] ?? null),
            self::timeOrNull($row['stopped_at'] ?? null),
            self::stringOf($row['recurrence'] ?? 'none'),
            self::timeOrNull($row['valid_until'] ?? null),
            self::timeOrNull($row['next_run_at'] ?? null),
            self::stringOrNull($row['recurrence_policy_version'] ?? null),
        );
    }

    public function tenantId(): int
    {
        return $this->tenantId;
    }

    public function id(): int
    {
        return $this->id;
    }

    public function authorizationId(): int
    {
        return $this->authorizationId;
    }

    public function profileId(): int
    {
        return $this->profileId;
    }

    public function profileVersion(): int
    {
        return $this->profileVersion;
    }

    public function status(): string
    {
        return $this->status;
    }

    public function isKillRequested(): bool
    {
        return $this->killRequested;
    }

    public function observedRequests(): int
    {
        return $this->observedRequests;
    }

    public function activeConcurrency(): int
    {
        return $this->activeConcurrency;
    }

    public function rateWindowStart(): ?DateTimeImmutable
    {
        return $this->rateWindowStart;
    }

    public function startedAt(): ?DateTimeImmutable
    {
        return $this->startedAt;
    }

    public function stoppedAt(): ?DateTimeImmutable
    {
        return $this->stoppedAt;
    }

    public function recurrence(): string
    {
        return $this->recurrence;
    }

    public function validUntil(): ?DateTimeImmutable
    {
        return $this->validUntil;
    }

    public function nextRunAt(): ?DateTimeImmutable
    {
        return $this->nextRunAt;
    }

    public function recurrencePolicyVersion(): ?string
    {
        return $this->recurrencePolicyVersion;
    }

    public function isRecurring(): bool
    {
        return $this->recurrence !== 'none';
    }

    /**
     * SFR-AUTH-001: an authorization's validity period has lapsed.
     *
     * A null valid_until means "no expiry". A non-null value lapses the instant
     * $now reaches or passes it, so an expired recurrence must not spawn a run.
     */
    public function isExpiredAt(DateTimeImmutable $now): bool
    {
        return $this->validUntil !== null
            && $this->validUntil->getTimestamp() <= $now->getTimestamp();
    }

    public function isRunning(): bool
    {
        return $this->status === self::STATUS_RUNNING;
    }

    /**
     * The flag the scanning loop polls between requests (SFR-SAFE-002).
     *
     * A paused scan stops the loop too: SBR-3.5 pauses on target instability,
     * and a pause that kept issuing requests would not be a pause.
     */
    public function shouldStop(): bool
    {
        return $this->killRequested
            || $this->status === self::STATUS_STOPPED
            || $this->status === self::STATUS_PAUSED
            || $this->status === self::STATUS_FAILED;
    }

    /**
     * Seconds this run has been going at $now, or null when it never started.
     *
     * Never negative: a started_at in the future (clock skew between the
     * writer and the caller) reads as 0 elapsed rather than as a wildly
     * negative number, so it cannot be mistaken for a duration breach.
     */
    public function elapsedSeconds(DateTimeImmutable $now): ?int
    {
        if ($this->startedAt === null) {
            return null;
        }

        return max(0, $now->getTimestamp() - $this->startedAt->getTimestamp());
    }

    private static function intOrNull(mixed $value): ?int
    {
        if ($value === null || $value === '') {
            return null;
        }

        return is_scalar($value) ? (int) $value : null;
    }

    private static function intOf(mixed $value): int
    {
        return is_scalar($value) ? (int) $value : 0;
    }

    private static function stringOrNull(mixed $value): ?string
    {
        if ($value === null || $value === '') {
            return null;
        }

        return is_scalar($value) ? (string) $value : null;
    }

    private static function stringOf(mixed $value): string
    {
        return is_scalar($value) ? (string) $value : '';
    }

    private static function boolOf(mixed $value): bool
    {
        return is_scalar($value) && (int) $value === 1;
    }

    /**
     * Parsed as UTC, to pair with the UTC strings ScanRepository writes. An
     * unparseable timestamp reads as absent, which makes the duration check
     * skip rather than guess.
     */
    private static function timeOrNull(mixed $value): ?DateTimeImmutable
    {
        if ($value === null || !is_scalar($value)) {
            return null;
        }

        $text = trim((string) $value);
        if ($text === '' || str_starts_with($text, '0000-00-00')) {
            return null;
        }

        try {
            return new DateTimeImmutable($text, new DateTimeZone('UTC'));
        } catch (Exception) {
            return null;
        }
    }
}
