<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Tenancy\TenantScope;
use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;

/**
 * One recorded sighting of a finding (SFR-FIND-002) - an immutable value
 * object, and deliberately a record of a HISTORICAL FACT.
 *
 * WHY THIS TYPE EXISTS AT ALL
 * ---------------------------
 * SFR-FIND-002 requires repeated evidence to update occurrence history WITHOUT
 * destroying previous state. A finding therefore cannot be a single mutable
 * row that the latest scan overwrites: the times it was seen, the runs that
 * saw it, and the evidence behind each sighting are all part of the record.
 * This object is one line of that history.
 *
 * WHY IT HAS NO "with..." METHOD AND NO SETTERS
 * ----------------------------------------------
 * Every other value object in this module offers a with*() that returns a
 * modified copy. This one does not, on purpose. An occurrence is the assertion
 * "at this moment, this run observed this finding on this asset with this
 * evidence" - and that assertion cannot become untrue later. There is no
 * legitimate edit, so the type offers no way to express one, and
 * FindingRepository only ever INSERTs into finding_occurrences.
 *
 * WHY THE EVIDENCE HASH IS CARRIED ALONGSIDE THE EVIDENCE ID
 * -----------------------------------------------------------
 * SFR-SELF-004 puts evidence under a retention policy, so the security_evidence
 * row backing an old sighting may legitimately be purged. Carrying the content
 * hash denormalised means the occurrence still says WHICH artifact it was, and
 * a later reader can still match two sightings as the same observation, after
 * the artifact itself is gone. The hash is a digest, never the content.
 *
 * © AI WebScapes 2026
 */
final class FindingOccurrence
{
    private const TIMESTAMP_FORMAT = 'Y-m-d H:i:s';

    public function __construct(
        private readonly int $tenantId,
        private readonly int $id,
        private readonly int $findingId,
        private readonly int $scanId,
        private readonly ?int $assetId,
        private readonly ?int $evidenceId,
        private readonly ?string $evidenceHash,
        private readonly DateTimeImmutable $observedAt,
        private readonly string $statusAtObservation,
        private readonly ?string $note = null,
    ) {
        // An occurrence outside a real tenant is not one anyone may read
        // (AC-001), so it cannot be constructed at all.
        if ($tenantId <= 0) {
            throw new InvalidArgumentException(
                'An occurrence must belong to a real tenant; 0 or negative is not a tenant (AC-001).'
            );
        }

        if ($findingId <= 0) {
            throw new InvalidArgumentException('An occurrence must reference a positive finding id.');
        }

        if ($scanId <= 0) {
            // A sighting nobody can attribute to a run is not evidence of
            // anything - it is an assertion with no provenance.
            throw new InvalidArgumentException(
                'An occurrence must reference the scan that observed it (SFR-FIND-002).'
            );
        }

        if ($evidenceHash !== null && trim($evidenceHash) === '') {
            throw new InvalidArgumentException('An evidence hash, when present, must be non-empty.');
        }

        // The status is recorded from the finding, so it uses the same
        // allowlist - an unknown value here would make the history unreadable.
        if (!in_array($statusAtObservation, Finding::STATUSES, true)) {
            throw new InvalidArgumentException(sprintf(
                'Unknown status "%s" recorded on an occurrence. It must be one of: %s.',
                $statusAtObservation,
                implode(', ', Finding::STATUSES)
            ));
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
            throw new InvalidArgumentException('An occurrence row must carry a positive id.');
        }

        $findingId = self::intOrNull($row['finding_id'] ?? null);
        if ($findingId === null || $findingId <= 0) {
            throw new InvalidArgumentException('An occurrence row must carry a positive finding id.');
        }

        $scanId = self::intOrNull($row['scan_id'] ?? null);
        if ($scanId === null || $scanId <= 0) {
            throw new InvalidArgumentException('An occurrence row must carry a positive scan id.');
        }

        return new self(
            $tenant->id(),
            $id,
            $findingId,
            $scanId,
            self::intOrNull($row['asset_id'] ?? null),
            self::intOrNull($row['evidence_id'] ?? null),
            self::stringOrNull($row['evidence_hash'] ?? null),
            self::timeOf($row['observed_at'] ?? null),
            self::stringOf($row['status_at_observation'] ?? null, Finding::STATUS_OPEN),
            self::stringOrNull($row['note'] ?? null),
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

    public function scanId(): int
    {
        return $this->scanId;
    }

    public function assetId(): ?int
    {
        return $this->assetId;
    }

    public function evidenceId(): ?int
    {
        return $this->evidenceId;
    }

    public function evidenceHash(): ?string
    {
        return $this->evidenceHash;
    }

    public function observedAt(): DateTimeImmutable
    {
        return $this->observedAt;
    }

    public function statusAtObservation(): string
    {
        return $this->statusAtObservation;
    }

    public function note(): ?string
    {
        return $this->note;
    }

    /**
     * The sanctioned projection for a report or an operator timeline.
     *
     * @return array{
     *     tenant_id: int,
     *     id: int,
     *     finding_id: int,
     *     scan_id: int,
     *     asset_id: int|null,
     *     evidence_id: int|null,
     *     evidence_hash: string|null,
     *     observed_at: string,
     *     status_at_observation: string,
     *     note: string|null
     * }
     */
    public function toReportArray(): array
    {
        return [
            'tenant_id' => $this->tenantId,
            'id' => $this->id,
            'finding_id' => $this->findingId,
            'scan_id' => $this->scanId,
            'asset_id' => $this->assetId,
            'evidence_id' => $this->evidenceId,
            'evidence_hash' => $this->evidenceHash,
            'observed_at' => $this->observedAt->format(self::TIMESTAMP_FORMAT),
            'status_at_observation' => $this->statusAtObservation,
            'note' => $this->note,
        ];
    }

    private static function intOrNull(mixed $value): ?int
    {
        if ($value === null || $value === '') {
            return null;
        }

        return is_scalar($value) ? (int) $value : null;
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
     * than coerced to "now", which would silently misdate the history.
     */
    private static function timeOf(mixed $value): DateTimeImmutable
    {
        if (!is_scalar($value) || (string) $value === '') {
            throw new InvalidArgumentException('An occurrence row must carry observed_at.');
        }

        $parsed = DateTimeImmutable::createFromFormat(
            self::TIMESTAMP_FORMAT,
            (string) $value,
            new DateTimeZone('UTC')
        );

        if ($parsed === false) {
            throw new InvalidArgumentException(sprintf(
                'Unreadable occurrence timestamp "%s"; expected %s in UTC.',
                (string) $value,
                self::TIMESTAMP_FORMAT
            ));
        }

        return $parsed;
    }
}
