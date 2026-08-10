<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Tenancy\TenantScope;
use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;

/**
 * One entry in the versioned asset inventory (SFR-ASSET-001) - an immutable
 * value object, never a live handle.
 *
 * WHAT SFR-ASSET-001 ACTUALLY ASKS FOR
 * ------------------------------------
 * Seven facts per asset: first seen, last seen, source, confidence, owner,
 * environment and criticality - plus the inventory being VERSIONED. This
 * object is the single place those are read from, so a report cannot quietly
 * omit one and a caller cannot invent one.
 *
 * WHY AN UPDATE IS A NEW VERSION AND NOT A MUTATION
 * -------------------------------------------------
 * bumpVersion() returns a NEW Asset rather than changing this one. Discovery
 * re-runs constantly, and an object that mutated in place would make "what did
 * we know about this host at the time of the scan?" unanswerable - the caller
 * holding the old value would silently see the new one. first_seen therefore
 * survives every bump: it is history, and history does not move.
 *
 * NO CLOCK OF ITS OWN ON THE BUMP PATH. bumpVersion() takes the moment as an
 * argument so the sighting time is the CALLER'S observed time, not whenever
 * this object happened to be constructed.
 *
 * © AI WebScapes 2026
 */
final class Asset
{
    private const TIMESTAMP_FORMAT = 'Y-m-d H:i:s';

    /**
     * @param array<string, mixed> $discoveryMeta
     */
    public function __construct(
        private readonly int $tenantId,
        private readonly int $id,
        private readonly string $canonicalAsset,
        private readonly string $assetType,
        private readonly int $version,
        private readonly string $environment,
        private readonly string $owner,
        private readonly string $criticality,
        private readonly string $confidence,
        private readonly DateTimeImmutable $firstSeen,
        private readonly DateTimeImmutable $lastSeen,
        private readonly string $source,
        private readonly array $discoveryMeta = [],
    ) {
        // An asset outside a real tenant is not an asset anyone may read
        // (AC-001), so it cannot be constructed at all. fromRow() puts the
        // value through TenantScope first, which refuses null as well.
        if ($tenantId <= 0) {
            throw new InvalidArgumentException(
                'An asset must belong to a real tenant; 0 or negative is not a tenant (AC-001).'
            );
        }

        if (trim($canonicalAsset) === '') {
            throw new InvalidArgumentException('An asset must carry a canonical identity.');
        }

        if ($version < 1) {
            throw new InvalidArgumentException('An asset version starts at 1 and only ever rises.');
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
            throw new InvalidArgumentException('An asset row must carry a positive id.');
        }

        return new self(
            $tenant->id(),
            $id,
            self::stringOf($row['canonical_asset'] ?? null),
            self::stringOf($row['asset_type'] ?? null, 'host'),
            max(1, self::intOf($row['version'] ?? null)),
            self::stringOf($row['environment'] ?? null, 'production'),
            self::stringOf($row['owner'] ?? null, ''),
            self::stringOf($row['criticality'] ?? null, 'medium'),
            self::stringOf($row['confidence'] ?? null, 'medium'),
            self::timeOf($row['first_seen'] ?? null),
            self::timeOf($row['last_seen'] ?? null),
            self::stringOf($row['source'] ?? null, 'asset-discovery'),
            self::decodeMeta($row['discovery_meta'] ?? null),
        );
    }

    /**
     * The next version of this asset, as a NEW object (SFR-ASSET-001).
     *
     * first_seen is carried over untouched - the point of the inventory is
     * that re-discovery does not erase when the asset was first observed.
     */
    public function bumpVersion(?DateTimeImmutable $seenAt = null): self
    {
        return new self(
            $this->tenantId,
            $this->id,
            $this->canonicalAsset,
            $this->assetType,
            $this->version + 1,
            $this->environment,
            $this->owner,
            $this->criticality,
            $this->confidence,
            $this->firstSeen,
            $seenAt ?? new DateTimeImmutable('now', new DateTimeZone('UTC')),
            $this->source,
            $this->discoveryMeta,
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

    public function canonicalAsset(): string
    {
        return $this->canonicalAsset;
    }

    public function assetType(): string
    {
        return $this->assetType;
    }

    public function version(): int
    {
        return $this->version;
    }

    public function environment(): string
    {
        return $this->environment;
    }

    public function owner(): string
    {
        return $this->owner;
    }

    public function criticality(): string
    {
        return $this->criticality;
    }

    public function confidence(): string
    {
        return $this->confidence;
    }

    public function firstSeen(): DateTimeImmutable
    {
        return $this->firstSeen;
    }

    public function lastSeen(): DateTimeImmutable
    {
        return $this->lastSeen;
    }

    public function source(): string
    {
        return $this->source;
    }

    /**
     * @return array<string, mixed>
     */
    public function discoveryMeta(): array
    {
        return $this->discoveryMeta;
    }

    /**
     * The sanctioned projection for a report: every fact SFR-ASSET-001 names,
     * in one place, with no live handles in it.
     *
     * @return array{
     *     tenant_id: int,
     *     id: int,
     *     canonical_asset: string,
     *     asset_type: string,
     *     version: int,
     *     environment: string,
     *     owner: string,
     *     criticality: string,
     *     confidence: string,
     *     first_seen: string,
     *     last_seen: string,
     *     source: string,
     *     discovery_meta: array<string, mixed>
     * }
     */
    public function toReportArray(): array
    {
        return [
            'tenant_id' => $this->tenantId,
            'id' => $this->id,
            'canonical_asset' => $this->canonicalAsset,
            'asset_type' => $this->assetType,
            'version' => $this->version,
            'environment' => $this->environment,
            'owner' => $this->owner,
            'criticality' => $this->criticality,
            'confidence' => $this->confidence,
            'first_seen' => $this->firstSeen->format(self::TIMESTAMP_FORMAT),
            'last_seen' => $this->lastSeen->format(self::TIMESTAMP_FORMAT),
            'source' => $this->source,
            'discovery_meta' => $this->discoveryMeta,
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
     * than coerced to "now", which would silently reset an asset's history.
     */
    private static function timeOf(mixed $value): DateTimeImmutable
    {
        if (!is_scalar($value) || (string) $value === '') {
            throw new InvalidArgumentException('An asset row must carry first_seen and last_seen.');
        }

        $parsed = DateTimeImmutable::createFromFormat(
            self::TIMESTAMP_FORMAT,
            (string) $value,
            new DateTimeZone('UTC')
        );

        if ($parsed === false) {
            throw new InvalidArgumentException(sprintf(
                'Unreadable asset timestamp "%s"; expected %s in UTC.',
                (string) $value,
                self::TIMESTAMP_FORMAT
            ));
        }

        return $parsed;
    }

    /**
     * @return array<string, mixed>
     */
    private static function decodeMeta(mixed $value): array
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
}
