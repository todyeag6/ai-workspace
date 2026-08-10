<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Tenancy\TenantScope;
use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;

/**
 * One remediation plan: the WORK of fixing a finding (FRD section 2 "Status,
 * owner, comments, exceptions, due dates, retest"; FRD section 4
 * `remediations` — "owner, plan, due, change reference, status").
 *
 * An immutable value object, never a live handle — the same shape as Finding
 * and Asset.
 *
 * WHY THIS IS NOT JUST security_findings.remediation
 * ---------------------------------------------------
 * The finding's `remediation` column is GUIDANCE: what somebody should do.
 * This object is the WORK: who owns it, by when, under which change reference,
 * and how far along it is. They are different tenses of the same word and
 * conflating them costs the fix its identity — SFR-RETEST-001 requires a
 * retest to link to "the original finding AND the remediation", so the
 * remediation has to be a thing a link can point at.
 *
 * WHY `verified` IS NOT A STATUS A CALLER CAN SIMPLY SET
 * ------------------------------------------------------
 * FRD section 7: "Closure requires passing evidence linked to remediation."
 * The whole point of that acceptance test is that the party claiming the fix
 * is not the party that gets to certify it. So while this object validates
 * that a status is a known one (AC-002), reaching STATUS_VERIFIED is gated by
 * RemediationTracker, which requires a passing, evidence-bearing retest row
 * linked to this remediation before RemediationRepository will write it. This
 * object exposes isVerified() as a question, never as a setter.
 *
 * WHY THE DUE DATE IS INHERITED, NOT INVENTED. due_at is seeded from the
 * finding's own SLA (Finding::slaDueAt(), itself derived from the ratified
 * config/security/FINDING_SLA.php). A remediation that quietly carried a
 * looser deadline than the finding it fixes would make the SLA unmeasurable —
 * two dates, and the flattering one wins. Extending a deadline is therefore a
 * deliberate, audited act (RemediationRepository::reschedule()), not a default.
 *
 * NO CLOCK OF ITS OWN. Every moment is passed in, so the record reflects when
 * something actually happened rather than when this object was constructed,
 * and every path stays deterministic under test.
 *
 * © AI WebScapes 2026
 */
final class Remediation
{
    private const TIMESTAMP_FORMAT = 'Y-m-d H:i:s';

    // -----------------------------------------------------------------
    // Status vocabulary (FRD section 4 "status"). An allowlist, not a
    // denylist (AC-002): an unrecognised status is refused rather than
    // stored and interpreted charitably later.
    // -----------------------------------------------------------------

    /** A plan exists. Nobody has started. The birth state. */
    public const STATUS_PLANNED = 'planned';

    /** Work is under way. */
    public const STATUS_IN_PROGRESS = 'in_progress';

    /** The owner says the fix is deployed. NOT yet proven — see below. */
    public const STATUS_FIX_APPLIED = 'fix_applied';

    /**
     * A passing, evidence-bearing retest linked to this remediation exists
     * (FRD section 7). The only status that constitutes proof, and the only
     * one no caller can assert directly.
     */
    public const STATUS_VERIFIED = 'verified';

    /** Work cannot proceed. An off-ramp that keeps the plan visible. */
    public const STATUS_BLOCKED = 'blocked';

    /** Abandoned — typically because the risk was formally accepted instead. */
    public const STATUS_CANCELLED = 'cancelled';

    /** @var list<string> */
    public const STATUSES = [
        self::STATUS_PLANNED,
        self::STATUS_IN_PROGRESS,
        self::STATUS_FIX_APPLIED,
        self::STATUS_VERIFIED,
        self::STATUS_BLOCKED,
        self::STATUS_CANCELLED,
    ];

    /**
     * The statuses that assert something about the WORLD rather than about
     * intent, and so require a named human.
     *
     * `fix_applied` is in this list deliberately: "the fix is deployed" is a
     * claim about production that somebody must own, even though it is not yet
     * the proof that `verified` demands.
     *
     * @var list<string>
     */
    public const HUMAN_ONLY_STATUSES = [
        self::STATUS_FIX_APPLIED,
        self::STATUS_VERIFIED,
        self::STATUS_CANCELLED,
    ];

    public function __construct(
        private readonly int $tenantId,
        private readonly int $id,
        private readonly int $findingId,
        private readonly string $owner,
        private readonly ?string $plan,
        private readonly ?DateTimeImmutable $dueAt,
        private readonly ?string $changeReference,
        private readonly string $status,
        private readonly string $createdBy,
        private readonly DateTimeImmutable $createdAt,
        private readonly DateTimeImmutable $updatedAt,
        private readonly ?string $verifiedBy = null,
        private readonly ?DateTimeImmutable $verifiedAt = null,
    ) {
        // A remediation outside a real tenant is not one anyone may read
        // (AC-001), so it cannot be constructed at all.
        if ($tenantId <= 0) {
            throw new InvalidArgumentException(
                'A remediation must belong to a real tenant; 0 or negative is not a tenant (AC-001).'
            );
        }

        if ($findingId <= 0) {
            throw new InvalidArgumentException(
                'A remediation must fix a real finding (FRD section 4, SFR-RETEST-001).'
            );
        }

        self::assertOneOf($status, self::STATUSES, 'status');

        // Fail closed on a contradiction the database would otherwise keep:
        // a verified remediation whose verifier is unnamed is exactly the
        // unevidenced closure FRD section 7 exists to prevent.
        if ($status === self::STATUS_VERIFIED && ($verifiedBy === null || trim($verifiedBy) === '')) {
            throw new InvalidArgumentException(
                'A verified remediation must name the human who verified it; closure requires '
                . 'passing evidence linked to remediation (FRD section 7, SFR-AI-001).'
            );
        }

        if ($updatedAt < $createdAt) {
            throw new InvalidArgumentException(
                'A remediation cannot be updated before it was created.'
            );
        }
    }

    /**
     * Builds the object from one database row.
     *
     * @param array<string, scalar|null> $row
     */
    public static function fromRow(array $row): self
    {
        // Throws for null / 0 / negative before anything else is read.
        $tenant = new TenantScope(self::intOrNull($row['tenant_id'] ?? null));

        $id = self::intOrNull($row['id'] ?? null);
        if ($id === null || $id <= 0) {
            throw new InvalidArgumentException('A remediation row must carry a positive id.');
        }

        $created = self::timeOf($row['created_at'] ?? null, 'created_at');

        return new self(
            $tenant->id(),
            $id,
            self::intOf($row['finding_id'] ?? null),
            self::stringOf($row['owner'] ?? null, ''),
            self::stringOrNull($row['plan'] ?? null),
            self::timeOrNull($row['due_at'] ?? null),
            self::stringOrNull($row['change_reference'] ?? null),
            self::stringOf($row['status'] ?? null, self::STATUS_PLANNED),
            self::stringOf($row['created_by'] ?? null, ''),
            $created,
            self::timeOrNull($row['updated_at'] ?? null) ?? $created,
            self::stringOrNull($row['verified_by'] ?? null),
            self::timeOrNull($row['verified_at'] ?? null),
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

    public function owner(): string
    {
        return $this->owner;
    }

    public function plan(): ?string
    {
        return $this->plan;
    }

    public function dueAt(): ?DateTimeImmutable
    {
        return $this->dueAt;
    }

    public function changeReference(): ?string
    {
        return $this->changeReference;
    }

    public function status(): string
    {
        return $this->status;
    }

    public function createdBy(): string
    {
        return $this->createdBy;
    }

    public function createdAt(): DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function updatedAt(): DateTimeImmutable
    {
        return $this->updatedAt;
    }

    public function verifiedBy(): ?string
    {
        return $this->verifiedBy;
    }

    public function verifiedAt(): ?DateTimeImmutable
    {
        return $this->verifiedAt;
    }

    /**
     * True once a passing retest has closed this out. Asked as a question
     * rather than compared as a string so a typo cannot silently report an
     * unverified fix as verified.
     */
    public function isVerified(): bool
    {
        return $this->status === self::STATUS_VERIFIED;
    }

    /**
     * True for a status that asserts something about the world and therefore
     * needs a named human (SFR-AI-001).
     */
    public function isHumanDecided(): bool
    {
        return in_array($this->status, self::HUMAN_ONLY_STATUSES, true);
    }

    /**
     * Whether the fix is still outstanding. Cancelled counts as settled: the
     * work is not happening and something else (typically a risk acceptance)
     * accounts for it.
     */
    public function isOpen(): bool
    {
        return !in_array($this->status, [self::STATUS_VERIFIED, self::STATUS_CANCELLED], true);
    }

    /**
     * Whether the remediation deadline has passed at the given moment.
     *
     * A verified or cancelled remediation is never overdue — it is no longer
     * chasing a deadline — and a null due date (informational findings) has no
     * clock to miss.
     */
    public function isOverdue(DateTimeImmutable $now): bool
    {
        if ($this->dueAt === null || !$this->isOpen()) {
            return false;
        }

        return $now > $this->dueAt;
    }

    /**
     * The sanctioned projection for a report (SFR-REPORT-001): every fact FRD
     * section 4 names, in one place, with no live handles in it.
     *
     * @return array{
     *     tenant_id: int,
     *     id: int,
     *     finding_id: int,
     *     owner: string,
     *     plan: string|null,
     *     due_at: string|null,
     *     change_reference: string|null,
     *     status: string,
     *     created_by: string,
     *     created_at: string,
     *     updated_at: string,
     *     verified_by: string|null,
     *     verified_at: string|null
     * }
     */
    public function toReportArray(): array
    {
        return [
            'tenant_id' => $this->tenantId,
            'id' => $this->id,
            'finding_id' => $this->findingId,
            'owner' => $this->owner,
            'plan' => $this->plan,
            'due_at' => $this->dueAt?->format(self::TIMESTAMP_FORMAT),
            'change_reference' => $this->changeReference,
            'status' => $this->status,
            'created_by' => $this->createdBy,
            'created_at' => $this->createdAt->format(self::TIMESTAMP_FORMAT),
            'updated_at' => $this->updatedAt->format(self::TIMESTAMP_FORMAT),
            'verified_by' => $this->verifiedBy,
            'verified_at' => $this->verifiedAt?->format(self::TIMESTAMP_FORMAT),
        ];
    }

    /**
     * @param list<string> $allowed
     */
    private static function assertOneOf(string $value, array $allowed, string $field): void
    {
        if (!in_array($value, $allowed, true)) {
            throw new InvalidArgumentException(sprintf(
                'Unknown remediation %s "%s". It must be one of: %s (allowlist, AC-002).',
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

    /**
     * A stored timestamp is read back as UTC, matching the way the repository
     * writes it. A value the database cannot have produced is refused rather
     * than coerced to "now", which would silently reset the record's history.
     */
    private static function timeOf(mixed $value, string $field): DateTimeImmutable
    {
        if (!is_scalar($value) || (string) $value === '') {
            throw new InvalidArgumentException(sprintf('A remediation row must carry %s.', $field));
        }

        $parsed = DateTimeImmutable::createFromFormat(
            self::TIMESTAMP_FORMAT,
            (string) $value,
            new DateTimeZone('UTC')
        );

        if ($parsed === false) {
            throw new InvalidArgumentException(sprintf(
                'Unreadable remediation timestamp "%s" for %s; expected %s in UTC.',
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
