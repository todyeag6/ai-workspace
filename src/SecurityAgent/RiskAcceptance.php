<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Tenancy\TenantScope;
use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;

/**
 * One formal acceptance of a risk that will not be fixed (FRD section 4
 * `risk_acceptances` — "approver, rationale, controls, expiry"; SBR-5.3).
 *
 * An immutable value object, never a live handle.
 *
 * SBR-5.3 VERBATIM: "Risk acceptance shall name approver, rationale,
 * compensating control, review date, and expiry."
 * ---------------------------------------------------------------------------
 * Five things. All five are constructor arguments with no default, and each is
 * refused when blank. That is the entire design of this class: the requirement
 * enumerates what an acceptance must NAME, so an acceptance missing any of
 * them cannot be constructed — not stored-then-validated, not warned about.
 * An exception register with blank approvers is the artefact SBR-5.3 exists to
 * prevent, and the cheapest place to prevent it is the type.
 *
 * WHY EXPIRY IS DERIVED, NOT STORED, AS A STATUS
 * -----------------------------------------------
 * There is a `status` column (active / revoked) but "expired" is NOT one of
 * its values. Whether an acceptance is still live is computed by comparing
 * expires_at against a clock the CALLER supplies (isActiveAt()). If expiry
 * were a stored status, an acceptance would remain "active" until some batch
 * job ran to expire it — meaning a lapsed waiver keeps suppressing a finding
 * because a cron job did not fire. Deriving it makes the passage of time
 * sufficient on its own, which is the fail-closed reading.
 *
 * WHY THE CLOCK IS ALWAYS A PARAMETER. Same rule as every other component in
 * this module: no `new DateTimeImmutable()` inside the class. A test can then
 * prove the expiry boundary exactly rather than sleeping.
 *
 * © AI WebScapes 2026
 */
final class RiskAcceptance
{
    private const TIMESTAMP_FORMAT = 'Y-m-d H:i:s';

    /** The acceptance stands, subject to its expiry. */
    public const STATUS_ACTIVE = 'active';

    /**
     * Withdrawn by a human before expiry — typically because the risk changed
     * or a fix became available.
     */
    public const STATUS_REVOKED = 'revoked';

    /**
     * Deliberately two values, not three. "Expired" is a function of the clock
     * (see the class comment), never a stored state.
     *
     * @var list<string>
     */
    public const STATUSES = [
        self::STATUS_ACTIVE,
        self::STATUS_REVOKED,
    ];

    public function __construct(
        private readonly int $tenantId,
        private readonly int $id,
        private readonly int $findingId,
        private readonly string $approver,
        private readonly string $rationale,
        private readonly string $compensatingControl,
        private readonly DateTimeImmutable $reviewAt,
        private readonly DateTimeImmutable $expiresAt,
        private readonly string $status,
        private readonly DateTimeImmutable $createdAt,
        private readonly ?string $revokedBy = null,
        private readonly ?DateTimeImmutable $revokedAt = null,
        private readonly ?string $revocationReason = null,
    ) {
        if ($tenantId <= 0) {
            throw new InvalidArgumentException(
                'A risk acceptance must belong to a real tenant; 0 or negative is not a tenant (AC-001).'
            );
        }

        if ($findingId <= 0) {
            throw new InvalidArgumentException(
                'A risk acceptance must concern a real finding (FRD section 4).'
            );
        }

        // SBR-5.3, one clause at a time. Each of these is a thing the
        // requirement says an acceptance shall NAME, so a blank one is not an
        // acceptance at all.
        if (trim($approver) === '') {
            throw new InvalidArgumentException(
                'A risk acceptance must name its approver (SBR-5.3). An unowned acceptance '
                . 'is the failure this requirement exists to prevent.'
            );
        }

        if (trim($rationale) === '') {
            throw new InvalidArgumentException(
                'A risk acceptance must state its rationale (SBR-5.3).'
            );
        }

        if (trim($compensatingControl) === '') {
            throw new InvalidArgumentException(
                'A risk acceptance must state its compensating control (SBR-5.3). "We accept it '
                . 'and do nothing" is a statable control; a blank field is not.'
            );
        }

        self::assertOneOf($status, self::STATUSES, 'status');

        // An acceptance that expires before it is reviewed inverts the point
        // of having both dates: the review exists so the decision is revisited
        // while it is still live.
        if ($reviewAt > $expiresAt) {
            throw new InvalidArgumentException(
                'A risk acceptance must be reviewed on or before it expires (SBR-5.3); a review '
                . 'scheduled after expiry reviews nothing.'
            );
        }

        if ($expiresAt <= $createdAt) {
            throw new InvalidArgumentException(
                'A risk acceptance must expire after it was granted (SBR-5.3).'
            );
        }

        if ($status === self::STATUS_REVOKED && ($revokedBy === null || trim($revokedBy) === '')) {
            // Same fail-closed shape as Remediation's verified check: a
            // revocation nobody owns is not a decision.
            throw new InvalidArgumentException(
                'A revoked risk acceptance must name the human who revoked it (SFR-AUD-001).'
            );
        }
    }

    /**
     * @param array<string, scalar|null> $row
     */
    public static function fromRow(array $row): self
    {
        $tenant = new TenantScope(self::intOrNull($row['tenant_id'] ?? null));

        $id = self::intOrNull($row['id'] ?? null);
        if ($id === null || $id <= 0) {
            throw new InvalidArgumentException('A risk acceptance row must carry a positive id.');
        }

        return new self(
            $tenant->id(),
            $id,
            self::intOf($row['finding_id'] ?? null),
            self::stringOf($row['approver'] ?? null, ''),
            self::stringOf($row['rationale'] ?? null, ''),
            self::stringOf($row['compensating_control'] ?? null, ''),
            self::timeOf($row['review_at'] ?? null, 'review_at'),
            self::timeOf($row['expires_at'] ?? null, 'expires_at'),
            self::stringOf($row['status'] ?? null, self::STATUS_ACTIVE),
            self::timeOf($row['created_at'] ?? null, 'created_at'),
            self::stringOrNull($row['revoked_by'] ?? null),
            self::timeOrNull($row['revoked_at'] ?? null),
            self::stringOrNull($row['revocation_reason'] ?? null),
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

    public function findingId(): int
    {
        return $this->findingId;
    }

    public function approver(): string
    {
        return $this->approver;
    }

    public function rationale(): string
    {
        return $this->rationale;
    }

    public function compensatingControl(): string
    {
        return $this->compensatingControl;
    }

    public function reviewAt(): DateTimeImmutable
    {
        return $this->reviewAt;
    }

    public function expiresAt(): DateTimeImmutable
    {
        return $this->expiresAt;
    }

    public function status(): string
    {
        return $this->status;
    }

    public function createdAt(): DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function revokedBy(): ?string
    {
        return $this->revokedBy;
    }

    public function revokedAt(): ?DateTimeImmutable
    {
        return $this->revokedAt;
    }

    public function revocationReason(): ?string
    {
        return $this->revocationReason;
    }

    /**
     * Whether this acceptance actually suppresses the finding at the given
     * moment (SBR-5.3).
     *
     * BOTH conditions, and the clock is the caller's: not revoked, AND not yet
     * expired. This is the only question the rest of the system should ask —
     * reading `status === 'active'` alone would treat a lapsed waiver as live.
     */
    public function isActiveAt(DateTimeImmutable $now): bool
    {
        return $this->status === self::STATUS_ACTIVE && $now <= $this->expiresAt;
    }

    /**
     * Whether the acceptance has passed its expiry at the given moment,
     * regardless of status.
     */
    public function hasExpiredAt(DateTimeImmutable $now): bool
    {
        return $now > $this->expiresAt;
    }

    /**
     * Whether a human owes this acceptance a review at the given moment
     * (SBR-5.3 "review date"). True from the review date onward while the
     * acceptance is still active — the window in which the decision can be
     * renewed or withdrawn before it lapses on its own.
     */
    public function isDueForReviewAt(DateTimeImmutable $now): bool
    {
        return $this->status === self::STATUS_ACTIVE && $now >= $this->reviewAt;
    }

    /**
     * The sanctioned projection for the exception / risk-acceptance register
     * the BRD names as a deliverable (BRD section 6, SFR-REPORT-001).
     *
     * @return array{
     *     tenant_id: int,
     *     id: int,
     *     finding_id: int,
     *     approver: string,
     *     rationale: string,
     *     compensating_control: string,
     *     review_at: string,
     *     expires_at: string,
     *     status: string,
     *     created_at: string,
     *     revoked_by: string|null,
     *     revoked_at: string|null,
     *     revocation_reason: string|null
     * }
     */
    public function toReportArray(): array
    {
        return [
            'tenant_id' => $this->tenantId,
            'id' => $this->id,
            'finding_id' => $this->findingId,
            'approver' => $this->approver,
            'rationale' => $this->rationale,
            'compensating_control' => $this->compensatingControl,
            'review_at' => $this->reviewAt->format(self::TIMESTAMP_FORMAT),
            'expires_at' => $this->expiresAt->format(self::TIMESTAMP_FORMAT),
            'status' => $this->status,
            'created_at' => $this->createdAt->format(self::TIMESTAMP_FORMAT),
            'revoked_by' => $this->revokedBy,
            'revoked_at' => $this->revokedAt?->format(self::TIMESTAMP_FORMAT),
            'revocation_reason' => $this->revocationReason,
        ];
    }

    /**
     * @param list<string> $allowed
     */
    private static function assertOneOf(string $value, array $allowed, string $field): void
    {
        if (!in_array($value, $allowed, true)) {
            throw new InvalidArgumentException(sprintf(
                'Unknown risk acceptance %s "%s". It must be one of: %s (allowlist, AC-002).',
                $field,
                $value,
                implode(', ', $allowed)
            ));
        }
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

    private static function stringOf(mixed $value, string $default = ''): string
    {
        if ($value === null || !is_scalar($value)) {
            return $default;
        }

        $string = (string) $value;

        return $string === '' ? $default : $string;
    }

    private static function stringOrNull(mixed $value): ?string
    {
        if ($value === null || !is_scalar($value)) {
            return null;
        }

        $string = (string) $value;

        return $string === '' ? null : $string;
    }

    private static function timeOf(mixed $value, string $field): DateTimeImmutable
    {
        if (!is_scalar($value) || (string) $value === '') {
            throw new InvalidArgumentException(sprintf(
                'A risk acceptance row must carry %s (SBR-5.3).',
                $field
            ));
        }

        $parsed = DateTimeImmutable::createFromFormat(
            self::TIMESTAMP_FORMAT,
            (string) $value,
            new DateTimeZone('UTC')
        );

        if ($parsed === false) {
            throw new InvalidArgumentException(sprintf(
                'Unreadable risk acceptance timestamp "%s" for %s; expected %s in UTC.',
                (string) $value,
                $field,
                self::TIMESTAMP_FORMAT
            ));
        }

        return $parsed;
    }

    private static function timeOrNull(mixed $value): ?DateTimeImmutable
    {
        if ($value === null || !is_scalar($value) || (string) $value === '') {
            return null;
        }

        $parsed = DateTimeImmutable::createFromFormat(
            self::TIMESTAMP_FORMAT,
            (string) $value,
            new DateTimeZone('UTC')
        );

        return $parsed === false ? null : $parsed;
    }
}
