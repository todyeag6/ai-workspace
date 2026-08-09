<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Tenancy\TenantScope;
use DateTimeImmutable;
use Exception;
use InvalidArgumentException;

/**
 * One recorded client authorization for defensive security testing
 * (SFR-AUTH-001, SBR-3.1) - an immutable value object, never a live handle.
 *
 * WHAT IT GUARANTEES
 * ------------------
 * SFR-AUTH-001 lists what must be present before anything is scheduled:
 * active authorization, tenant, target, technique profile, validity period and
 * stop contact. Five of those six live on this object and are checked by
 * isComplete(); the sixth (target) is the scan_targets list, checked per
 * request by ScopeManager because a single authorization covers many targets
 * and a redirect can produce a new one mid-scan.
 *
 * WHY 'active' IS NOT ENOUGH ON ITS OWN
 * ------------------------------------
 * A stored status is a claim about the past. isActive() therefore re-derives
 * the answer from the recorded facts every time it is asked: the status must
 * be 'active', the record must be COMPLETE, and $now must fall inside
 * [valid_from, valid_to]. A row that reached 'active' with a NULL validity end
 * - through a migration, a fixture or a hand-written UPDATE - is refused, so
 * the P3 acceptance test "expired authorization -> scan cannot start" holds
 * even against a database that was written around the application.
 *
 * SFR-AUTH-003 AND WHAT IS ABSENT
 * -------------------------------
 * There is no credential property. The object carries the FINGERPRINT only,
 * so no report, log line, var_dump or json_encode of an Authorization can leak
 * a credential: the material is simply not in the object graph. toReportArray()
 * is the sanctioned report projection and omits even the ciphertext.
 *
 * © AI WebScapes 2026
 */
final class Authorization
{
    /**
     * @param list<string> $techniqueProfile
     */
    public function __construct(
        private readonly int $tenantId,
        private readonly int $id,
        private readonly string $clientName,
        private readonly string $status,
        private readonly ?DateTimeImmutable $validFrom,
        private readonly ?DateTimeImmutable $validTo,
        private readonly array $techniqueProfile,
        private readonly string $stopContact,
        private readonly string $ownershipProofType,
        private readonly string $ownershipProofRef,
        private readonly ?string $credentialsFingerprint = null,
    ) {
    }

    /**
     * Builds the object from one database row.
     *
     * The tenant is validated through TenantScope, which throws for null, 0 or
     * negative - the same gate every repository passes through, so an
     * Authorization cannot exist outside a real tenant (AC-001).
     *
     * @param array<string, scalar|null> $row
     */
    public static function fromRow(array $row): self
    {
        $tenantId = self::intOrNull($row['tenant_id'] ?? null);
        // Throws UnscopedQueryException for null / 0 / negative.
        $tenant = new TenantScope($tenantId);

        $id = self::intOrNull($row['id'] ?? null);
        if ($id === null || $id <= 0) {
            throw new InvalidArgumentException('An authorization row must carry a positive id.');
        }

        return new self(
            $tenant->id(),
            $id,
            self::stringOf($row['client_name'] ?? null),
            self::stringOf($row['status'] ?? null),
            self::timeOrNull($row['valid_from'] ?? null),
            self::timeOrNull($row['valid_to'] ?? null),
            self::decodeProfile($row['technique_profile'] ?? null),
            self::stringOf($row['stop_contact'] ?? null),
            self::stringOf($row['ownership_proof_type'] ?? null),
            self::stringOf($row['ownership_proof_ref'] ?? null),
            self::nullableStringOf($row['credentials_fingerprint'] ?? null),
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

    public function clientName(): string
    {
        return $this->clientName;
    }

    public function status(): string
    {
        return $this->status;
    }

    public function stopContact(): string
    {
        return $this->stopContact;
    }

    public function ownershipProofType(): string
    {
        return $this->ownershipProofType;
    }

    public function ownershipProofRef(): string
    {
        return $this->ownershipProofRef;
    }

    public function credentialsFingerprint(): ?string
    {
        return $this->credentialsFingerprint;
    }

    /**
     * @return list<string>
     */
    public function techniqueProfile(): array
    {
        return $this->techniqueProfile;
    }

    /**
     * SFR-AUTH-001 / SBR-3.1: everything that must be RECORDED is recorded.
     *
     * Deliberately separate from isActive() so a caller can tell "this
     * authorization was never finished" from "this authorization has expired".
     */
    public function isComplete(): bool
    {
        return $this->clientName !== ''
            && $this->stopContact !== ''
            && $this->techniqueProfile !== []
            && $this->ownershipProofType !== ''
            && $this->ownershipProofRef !== ''
            && $this->validFrom !== null
            && $this->validTo !== null
            && $this->validFrom <= $this->validTo;
    }

    /**
     * Active means: recorded completely, marked active, and inside the agreed
     * window at the instant asked about. $now is injected, never read from the
     * clock here, so the decision is deterministic and testable.
     */
    public function isActive(DateTimeImmutable $now): bool
    {
        if ($this->status !== 'active' || !$this->isComplete()) {
            return false;
        }

        // isComplete() has already proven both bounds are present; the checks
        // are repeated here only because the compiler cannot know that.
        return $this->validFrom !== null
            && $this->validTo !== null
            && $now >= $this->validFrom
            && $now <= $this->validTo;
    }

    /**
     * SFR-AUTH-001: nothing is scheduled without an active authorization.
     * Identical to isActive() by design - a separate name is kept because the
     * requirement is phrased about scheduling and callers read better for it.
     */
    public function canSchedule(DateTimeImmutable $now): bool
    {
        return $this->isActive($now);
    }

    public function expiresAt(): ?DateTimeImmutable
    {
        return $this->validTo;
    }

    public function startsAt(): ?DateTimeImmutable
    {
        return $this->validFrom;
    }

    /**
     * The ONLY sanctioned projection for reports (SFR-AUTH-003).
     *
     * Credential material is absent by construction, and the ciphertext is
     * omitted as well: a report that carries an encrypted blob is one key
     * disclosure away from carrying the secret, and no report needs it.
     *
     * @return array{
     *     tenant_id: int,
     *     id: int,
     *     client_name: string,
     *     status: string,
     *     valid_from: string|null,
     *     valid_to: string|null,
     *     technique_profile: list<string>,
     *     stop_contact: string,
     *     ownership_proof_type: string,
     *     ownership_proof_ref: string,
     *     credentials_fingerprint: string|null
     * }
     */
    public function toReportArray(): array
    {
        return [
            'tenant_id' => $this->tenantId,
            'id' => $this->id,
            'client_name' => $this->clientName,
            'status' => $this->status,
            'valid_from' => $this->validFrom?->format('Y-m-d H:i:s'),
            'valid_to' => $this->validTo?->format('Y-m-d H:i:s'),
            'technique_profile' => $this->techniqueProfile,
            'stop_contact' => $this->stopContact,
            'ownership_proof_type' => $this->ownershipProofType,
            'ownership_proof_ref' => $this->ownershipProofRef,
            'credentials_fingerprint' => $this->credentialsFingerprint,
        ];
    }

    private static function intOrNull(mixed $value): ?int
    {
        if ($value === null || $value === '') {
            return null;
        }

        return is_scalar($value) ? (int) $value : null;
    }

    private static function stringOf(mixed $value): string
    {
        return is_scalar($value) ? (string) $value : '';
    }

    private static function nullableStringOf(mixed $value): ?string
    {
        if ($value === null) {
            return null;
        }

        return is_scalar($value) ? (string) $value : null;
    }

    /**
     * A stored timestamp that cannot be parsed is treated as ABSENT rather
     * than as "now" or as an exception: an unreadable validity bound must make
     * the authorization unschedulable, which is what null does here.
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
            return new DateTimeImmutable($text);
        } catch (Exception) {
            return null;
        }
    }

    /**
     * @return list<string>
     */
    private static function decodeProfile(mixed $value): array
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
