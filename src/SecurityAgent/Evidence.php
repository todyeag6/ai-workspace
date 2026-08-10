<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Tenancy\TenantScope;
use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;

/**
 * One item of recorded scan evidence (SFR-EVID-001, SFR-EVID-002) - an
 * immutable value object, never a live handle.
 *
 * WHAT SFR-EVID-001 ACTUALLY ASKS FOR
 * -----------------------------------
 * Evidence shall include scanner/version, target, timestamp, request category,
 * response metadata, reproduction and a cryptographic hash. This object is the
 * single place those are read from, so a report cannot quietly omit one and a
 * caller cannot invent one. Everything SFR-EVID-001 names is a field here.
 *
 * WHY THE HASH LIVES ON THE OBJECT. SFR-EVID-001 requires the hash "where
 * stored as artifact" - the digest is part of the evidence's identity, not a
 * side calculation someone performs later. Carrying it makes "this is the
 * artifact we collected, and it has not changed" a question the object answers
 * by inspection.
 *
 * WHY REDACTION IS ON THE OBJECT, NOT A LATER PROCESS. SFR-EVID-002 says
 * secrets, session identifiers, personal data and unnecessary response bodies
 * shall be redacted before routine display. redactedAt()/redactionKinds() are
 * the record of that scrub: a NULL redacted_at means the item was clean as
 * submitted, a timestamp means the processor removed sensitive material first,
 * and the kinds list is the one-way fingerprint of WHAT was removed (never the
 * values). That is exactly what a report is allowed to show.
 *
 * NO CLOCK OF ITS OWN ON THE STORE PATH. The evidence is built from values
 * other components hand in - the capture moment is the caller's observed time,
 * not whatever this object happened to be constructed at.
 *
 * © AI WebScapes 2026
 */
final class Evidence
{
    private const TIMESTAMP_FORMAT = 'Y-m-d H:i:s';

    /**
     * @param array<string, mixed>      $responseMetadata Structured what-the-target-returned.
     * @param array<string, mixed>|null $reproduction     The re-runnable recipe, or null when none.
     * @param list<string>|null         $redactionKinds   The one-way fingerprint of removed kinds.
     */
    public function __construct(
        private readonly int $tenantId,
        private readonly int $id,
        private readonly int $scanId,
        private readonly ?int $assetId,
        private readonly string $scanner,
        private readonly string $scannerVersion,
        private readonly string $target,
        private readonly DateTimeImmutable $capturedAt,
        private readonly string $requestCategory,
        private readonly array $responseMetadata,
        private readonly ?array $reproduction,
        private readonly string $contentHash,
        private readonly ?DateTimeImmutable $redactedAt,
        private readonly ?array $redactionKinds,
    ) {
        // An evidence item outside a real tenant is not one anyone may read
        // (AC-001), so it cannot be constructed at all. fromRow() puts the
        // value through TenantScope first, which refuses null as well.
        if ($tenantId <= 0) {
            throw new InvalidArgumentException(
                'Evidence must belong to a real tenant; 0 or negative is not a tenant (AC-001).'
            );
        }

        if ($scanId <= 0) {
            throw new InvalidArgumentException('Evidence must reference a positive scan id.');
        }

        if (trim($scanner) === '') {
            throw new InvalidArgumentException('Evidence must name the scanner that produced it (SFR-EVID-001).');
        }

        if (trim($scannerVersion) === '') {
            throw new InvalidArgumentException('Evidence must name the scanner version (SFR-EVID-001, SFR-SELF-002).');
        }

        if (trim($target) === '') {
            throw new InvalidArgumentException('Evidence must name the target it concerns (SFR-EVID-001).');
        }

        if (trim($contentHash) === '') {
            throw new InvalidArgumentException('Evidence must carry a content hash (SFR-EVID-001).');
        }

        if ($redactionKinds !== null) {
            foreach ($redactionKinds as $kind) {
                if (trim($kind) === '') {
                    throw new InvalidArgumentException('A redaction kind must be a non-empty string.');
                }
            }
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
            throw new InvalidArgumentException('An evidence row must carry a positive id.');
        }

        $scanId = self::intOrNull($row['scan_id'] ?? null);
        if ($scanId === null || $scanId <= 0) {
            throw new InvalidArgumentException('An evidence row must carry a positive scan id.');
        }

        $assetId = self::intOrNull($row['asset_id'] ?? null);

        return new self(
            $tenant->id(),
            $id,
            $scanId,
            $assetId,
            self::stringOf($row['scanner'] ?? null),
            self::stringOf($row['scanner_version'] ?? null),
            self::stringOf($row['target'] ?? null),
            self::timeOf($row['captured_at'] ?? null),
            self::stringOf($row['request_category'] ?? null, 'uncategorized'),
            self::decodeJson($row['response_metadata'] ?? null),
            self::decodeJson($row['reproduction'] ?? null),
            self::stringOf($row['content_hash'] ?? null),
            self::timeOrNull($row['redacted_at'] ?? null),
            self::decodeKinds($row['redaction_fingerprints'] ?? null)
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

    public function scanId(): int
    {
        return $this->scanId;
    }

    public function assetId(): ?int
    {
        return $this->assetId;
    }

    public function scanner(): string
    {
        return $this->scanner;
    }

    public function scannerVersion(): string
    {
        return $this->scannerVersion;
    }

    public function target(): string
    {
        return $this->target;
    }

    public function capturedAt(): DateTimeImmutable
    {
        return $this->capturedAt;
    }

    public function requestCategory(): string
    {
        return $this->requestCategory;
    }

    /**
     * @return array<string, mixed>
     */
    public function responseMetadata(): array
    {
        return $this->responseMetadata;
    }

    /**
     * @return array<string, mixed>|null
     */
    public function reproduction(): ?array
    {
        return $this->reproduction;
    }

    public function contentHash(): string
    {
        return $this->contentHash;
    }

    public function redactedAt(): ?DateTimeImmutable
    {
        return $this->redactedAt;
    }

    /**
     * The one-way fingerprint of what kinds of sensitive data were removed.
     *
     * @return list<string>
     */
    public function redactionKinds(): array
    {
        return $this->redactionKinds ?? [];
    }

    public function wasRedacted(): bool
    {
        return $this->redactedAt !== null;
    }

    /**
     * The sanctioned projection for routine display (SFR-EVID-002). It omits
     * the raw response body entirely - the contract is that nothing sensitive
     * is exposed by construction, and the kinds list is the only redaction
     * trace that travels.
     *
     * @return array{
     *     tenant_id: int,
     *     id: int,
     *     scan_id: int,
     *     asset_id: int|null,
     *     scanner: string,
     *     scanner_version: string,
     *     target: string,
     *     captured_at: string,
     *     request_category: string,
     *     response_metadata: array<string, mixed>,
     *     reproduction: array<string, mixed>|null,
     *     content_hash: string,
     *     redacted_at: string|null,
     *     redaction_kinds: list<string>
     * }
     */
    public function toReportArray(): array
    {
        return [
            'tenant_id' => $this->tenantId,
            'id' => $this->id,
            'scan_id' => $this->scanId,
            'asset_id' => $this->assetId,
            'scanner' => $this->scanner,
            'scanner_version' => $this->scannerVersion,
            'target' => $this->target,
            'captured_at' => $this->capturedAt->format(self::TIMESTAMP_FORMAT),
            'request_category' => $this->requestCategory,
            'response_metadata' => $this->responseMetadata,
            'reproduction' => $this->reproduction,
            'content_hash' => $this->contentHash,
            'redacted_at' => $this->redactedAt?->format(self::TIMESTAMP_FORMAT),
            'redaction_kinds' => $this->redactionKinds(),
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

    /**
     * A stored timestamp is read back as UTC, matching the way the repository
     * writes it. A value the database cannot have produced is refused rather
     * than coerced to "now", which would silently reset an evidence timeline.
     */
    private static function timeOf(mixed $value): DateTimeImmutable
    {
        if (!is_scalar($value) || (string) $value === '') {
            throw new InvalidArgumentException('An evidence row must carry captured_at.');
        }

        $parsed = DateTimeImmutable::createFromFormat(
            self::TIMESTAMP_FORMAT,
            (string) $value,
            new DateTimeZone('UTC')
        );

        if ($parsed === false) {
            throw new InvalidArgumentException(sprintf(
                'Unreadable evidence timestamp "%s"; expected %s in UTC.',
                (string) $value,
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

    /**
     * @return array<string, mixed>
     */
    private static function decodeJson(mixed $value): array
    {
        if (!is_string($value) || trim($value) === '') {
            return [];
        }

        $decoded = json_decode($value, true);
        if (!is_array($decoded)) {
            return [];
        }

        $clean = [];
        foreach ($decoded as $key => $entry) {
            if (is_string($key)) {
                $clean[$key] = $entry;
            }
        }

        return $clean;
    }

    /**
     * @return list<string>|null
     */
    private static function decodeKinds(mixed $value): ?array
    {
        $decoded = self::decodeJson($value);
        if ($decoded === []) {
            return null;
        }

        $kinds = [];
        foreach ($decoded as $kind) {
            if (is_string($kind) && trim($kind) !== '') {
                $kinds[] = $kind;
            }
        }

        return $kinds === [] ? null : $kinds;
    }
}
