<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Tenancy\TenantScope;
use InvalidArgumentException;

/**
 * The approved safety envelope for a scan (SFR-SAFE-001, SFR-SAFE-003,
 * SBR-3.3) - an immutable value object, never a live handle.
 *
 * WHAT IT IS FOR
 * --------------
 * SFR-SAFE-001 lists six limits that EVERY scan must enforce: concurrency,
 * request rate, timeout, payload size, retries and duration. This object is
 * the single place those six are read from, so the SafetyMonitor cannot
 * enforce a limit that nobody approved and cannot skip one that was.
 *
 * WHY DESTRUCTIVE IS TWO FLAGS AND NOT ONE
 * ----------------------------------------
 * SFR-SAFE-003 requires destructive checks to be disabled by default AND to
 * require a separately approved profile. Those are two different facts -
 * "this profile asks for destructive checks" and "someone with authority
 * signed that off" - and collapsing them into one boolean would let whoever
 * writes the profile also grant the approval. isDestructiveEnabled() and
 * isDestructiveApproved() stay separate for that reason, and SafetyMonitor
 * refuses unless both are true.
 *
 * NO CLOCK, NO DATABASE, NO DECISIONS
 * -----------------------------------
 * This object answers questions about a recorded envelope. It does not judge
 * a request against it - SafetyMonitor does - which keeps the thing being
 * enforced separate from the thing doing the enforcing.
 *
 * © AI WebScapes 2026
 */
final class ScanProfile
{
    /**
     * @param list<string> $checks
     */
    public function __construct(
        private readonly int $tenantId,
        private readonly int $id,
        private readonly int $authorizationId,
        private readonly int $version,
        private readonly array $checks,
        private readonly bool $destructiveChecksEnabled,
        private readonly bool $destructiveApproved,
        private readonly int $concurrencyLimit,
        private readonly int $rateLimitPerMin,
        private readonly int $requestTimeoutSec,
        private readonly int $maxPayloadBytes,
        private readonly int $maxRetries,
        private readonly int $maxDurationSec,
        private readonly bool $immutableAfterUse = false,
    ) {
    }

    /**
     * Builds the object from one database row.
     *
     * The tenant goes through TenantScope, which throws for null, 0 or
     * negative - so a ScanProfile cannot exist outside a real tenant (AC-001).
     *
     * @param array<string, scalar|null> $row
     */
    public static function fromRow(array $row): self
    {
        // Throws UnscopedQueryException for null / 0 / negative.
        $tenant = new TenantScope(self::intOrNull($row['tenant_id'] ?? null));

        $id = self::intOrNull($row['id'] ?? null);
        if ($id === null || $id <= 0) {
            throw new InvalidArgumentException('A scan profile row must carry a positive id.');
        }

        return new self(
            $tenant->id(),
            $id,
            self::intOf($row['authorization_id'] ?? null),
            self::intOf($row['version'] ?? null),
            self::decodeChecks($row['checks'] ?? null),
            self::boolOf($row['destructive_checks_enabled'] ?? null),
            self::boolOf($row['destructive_approved'] ?? null),
            self::intOf($row['concurrency_limit'] ?? null),
            self::intOf($row['rate_limit_per_min'] ?? null),
            self::intOf($row['request_timeout_sec'] ?? null),
            self::intOf($row['max_payload_bytes'] ?? null),
            self::intOf($row['max_retries'] ?? null),
            self::intOf($row['max_duration_sec'] ?? null),
            self::boolOf($row['immutable_after_use'] ?? null),
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

    public function version(): int
    {
        return $this->version;
    }

    /**
     * @return list<string>
     */
    public function checks(): array
    {
        return $this->checks;
    }

    /**
     * SFR-SAFE-003: false unless the profile explicitly asked for destructive
     * checks. The column defaults to 0, so silence means non-destructive.
     */
    public function isDestructiveEnabled(): bool
    {
        return $this->destructiveChecksEnabled;
    }

    /**
     * SFR-SAFE-003: the separate sign-off. Enabling does not imply approval,
     * and an approval on a profile that never enabled destructive checks is
     * refused at the repository (there is nothing to approve).
     */
    public function isDestructiveApproved(): bool
    {
        return $this->destructiveApproved;
    }

    /**
     * The question SafetyMonitor actually asks: may destructive checks run?
     * Both facts, never one.
     */
    public function mayRunDestructiveChecks(): bool
    {
        return $this->destructiveChecksEnabled && $this->destructiveApproved;
    }

    public function isImmutable(): bool
    {
        return $this->immutableAfterUse;
    }

    // ---- SFR-SAFE-001: the six limits ------------------------------

    public function concurrencyLimit(): int
    {
        return $this->concurrencyLimit;
    }

    public function rateLimitPerMin(): int
    {
        return $this->rateLimitPerMin;
    }

    public function requestTimeoutSec(): int
    {
        return $this->requestTimeoutSec;
    }

    public function maxPayloadBytes(): int
    {
        return $this->maxPayloadBytes;
    }

    public function maxRetries(): int
    {
        return $this->maxRetries;
    }

    public function maxDurationSec(): int
    {
        return $this->maxDurationSec;
    }

    /**
     * The sanctioned projection for a report: the envelope a client was
     * scanned under, in one place, with no live handles in it.
     *
     * @return array{
     *     tenant_id: int,
     *     id: int,
     *     authorization_id: int,
     *     version: int,
     *     checks: list<string>,
     *     destructive_checks_enabled: bool,
     *     destructive_approved: bool,
     *     concurrency_limit: int,
     *     rate_limit_per_min: int,
     *     request_timeout_sec: int,
     *     max_payload_bytes: int,
     *     max_retries: int,
     *     max_duration_sec: int
     * }
     */
    public function toReportArray(): array
    {
        return [
            'tenant_id' => $this->tenantId,
            'id' => $this->id,
            'authorization_id' => $this->authorizationId,
            'version' => $this->version,
            'checks' => $this->checks,
            'destructive_checks_enabled' => $this->destructiveChecksEnabled,
            'destructive_approved' => $this->destructiveApproved,
            'concurrency_limit' => $this->concurrencyLimit,
            'rate_limit_per_min' => $this->rateLimitPerMin,
            'request_timeout_sec' => $this->requestTimeoutSec,
            'max_payload_bytes' => $this->maxPayloadBytes,
            'max_retries' => $this->maxRetries,
            'max_duration_sec' => $this->maxDurationSec,
        ];
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

    /**
     * A stored flag is read as a flag: anything that is not a truthy scalar is
     * false, so an unreadable value fails SAFE rather than enabling a
     * destructive check (SFR-SAFE-003).
     */
    private static function boolOf(mixed $value): bool
    {
        return is_scalar($value) && (int) $value === 1;
    }

    /**
     * @return list<string>
     */
    private static function decodeChecks(mixed $value): array
    {
        if (is_array($value)) {
            return self::stringList($value);
        }

        if (!is_string($value) || trim($value) === '') {
            return [];
        }

        $decoded = json_decode($value, true);

        return is_array($decoded) ? self::stringList($decoded) : [];
    }

    /**
     * @param  array<array-key, mixed> $values
     * @return list<string>
     */
    private static function stringList(array $values): array
    {
        $clean = [];
        foreach ($values as $value) {
            if (is_scalar($value)) {
                $clean[] = (string) $value;
            }
        }

        return $clean;
    }
}
