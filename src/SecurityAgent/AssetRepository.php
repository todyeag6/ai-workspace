<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Data\TenantRepository;
use DateTimeImmutable;
use DateTimeZone;
use JsonException;
use RuntimeException;

/**
 * Tenant-scoped persistence for the asset inventory (SFR-ASSET-001).
 *
 * WHY THE WRITE PATH IS AN UPSERT AND NOT AN INSERT
 * -------------------------------------------------
 * Discovery re-runs. If every pass inserted, the inventory would accumulate a
 * new copy of the same host per run and "first seen" would become "seen by the
 * most recent scan" - which is precisely the fact SFR-ASSET-001 exists to
 * preserve. upsert() therefore finds the row by its canonical identity and
 * bumps it: version + 1, last_seen moved, first_seen untouched.
 *
 * WHY A SIGHTING DOES NOT ERASE WHAT IT DOES NOT MENTION
 * ------------------------------------------------------
 * A passive DNS pass knows a hostname but nothing about ownership or
 * criticality. If an upsert wrote defaults for the attributes it was not told
 * about, the second sighting would silently downgrade an asset a human had
 * classified as critical. Only the keys actually supplied are written.
 *
 * WHY TIMESTAMPS COME FROM PHP IN UTC. Same reason as ScanRepository: the
 * inventory is compared against application-side clocks (scan windows, drift
 * reports), so a value written by the database session's clock could sit in a
 * different zone from the value it is compared with. The caller may inject the
 * sighting moment, which also makes the versioning deterministic under test.
 *
 * AC-001 comes from the base class: construction builds a TenantScope, and
 * every statement carries `tenant_id = :tenant` bound internally.
 *
 * © AI WebScapes 2026
 */
final class AssetRepository extends TenantRepository
{
    private const TIMESTAMP_FORMAT = 'Y-m-d H:i:s';

    private const DEFAULT_TYPE = 'host';

    /** Attributes a sighting may state. Anything else in $meta is ignored. */
    private const WRITABLE = [
        'environment',
        'owner',
        'criticality',
        'confidence',
        'source',
    ];

    protected function table(): string
    {
        return 'security_assets';
    }

    /**
     * @return list<string>
     */
    protected function columns(): array
    {
        return [
            'id',
            'tenant_id',
            'canonical_asset',
            'asset_type',
            'version',
            'environment',
            'owner',
            'criticality',
            'confidence',
            'first_seen',
            'last_seen',
            'source',
            'discovery_meta',
        ];
    }

    /**
     * Records a sighting of one asset and returns its inventory id.
     *
     * First sighting inserts at version 1 with first_seen = last_seen = now.
     * Every later sighting bumps the version, moves last_seen and MERGES the
     * discovery metadata, leaving first_seen alone (SFR-ASSET-001).
     *
     * @param array<string, mixed> $meta Optional attributes: asset_type,
     *                                   environment, owner, criticality,
     *                                   confidence, source, discovery_meta.
     */
    public function upsert(string $canonicalAsset, array $meta = [], ?DateTimeImmutable $now = null): int
    {
        $canonical = trim($canonicalAsset);
        if ($canonical === '') {
            throw new RuntimeException('An asset sighting must name a canonical asset.');
        }

        $type = $this->stringFrom($meta, 'asset_type', self::DEFAULT_TYPE);
        $stamp = ($now ?? $this->clock())->format(self::TIMESTAMP_FORMAT);
        $existing = $this->findByCanonicalAndType($canonical, $type);

        if ($existing === null) {
            return (int) $this->insertScoped([
                'canonical_asset' => $canonical,
                'asset_type' => $type,
                'version' => 1,
                'environment' => $this->stringFrom($meta, 'environment', 'production'),
                'owner' => $this->stringFrom($meta, 'owner', ''),
                'criticality' => $this->stringFrom($meta, 'criticality', 'medium'),
                'confidence' => $this->stringFrom($meta, 'confidence', 'medium'),
                // Written once, here, and never updated again.
                'first_seen' => $stamp,
                'last_seen' => $stamp,
                'source' => $this->stringFrom($meta, 'source', 'asset-discovery'),
                'discovery_meta' => $this->encodeMeta($this->metaFrom($meta)),
            ]);
        }

        $values = [
            'version' => $existing->version() + 1,
            'last_seen' => $stamp,
            'discovery_meta' => $this->encodeMeta(
                array_merge($existing->discoveryMeta(), $this->metaFrom($meta))
            ),
        ];

        // Only what this sighting actually claims is written.
        foreach (self::WRITABLE as $attribute) {
            if (array_key_exists($attribute, $meta)) {
                $values[$attribute] = $this->stringFrom($meta, $attribute, '');
            }
        }

        $this->updateScoped($values, 'id = :id', ['id' => $existing->id()]);

        return $existing->id();
    }

    /**
     * Null both when the asset does not exist and when it belongs to another
     * tenant - deliberately indistinguishable (AC-001).
     */
    public function findById(int $id): ?Asset
    {
        $rows = $this->selectScoped('id = :id', ['id' => $id]);
        if ($rows === []) {
            return null;
        }

        return Asset::fromRow($rows[0]);
    }

    /**
     * Every recorded type for one canonical identity within this tenant - a
     * name can be both a domain and a host, and they are different assets.
     *
     * @return list<Asset>
     */
    public function findByCanonical(string $canonicalAsset): array
    {
        $rows = $this->selectScoped(
            'canonical_asset = :asset',
            ['asset' => trim($canonicalAsset)]
        );

        $assets = [];
        foreach ($rows as $row) {
            $assets[] = Asset::fromRow($row);
        }

        return $assets;
    }

    /**
     * @throws RuntimeException When no such asset exists in this tenant.
     */
    public function requireById(int $id): Asset
    {
        $asset = $this->findById($id);
        if ($asset === null) {
            throw new RuntimeException(sprintf(
                'Asset %d does not exist for tenant %d.',
                $id,
                $this->tenantId()
            ));
        }

        return $asset;
    }

    private function findByCanonicalAndType(string $canonical, string $type): ?Asset
    {
        $rows = $this->selectScoped(
            'canonical_asset = :asset AND asset_type = :asset_type',
            ['asset' => $canonical, 'asset_type' => $type]
        );

        if ($rows === []) {
            return null;
        }

        return Asset::fromRow($rows[0]);
    }

    /**
     * @param array<string, mixed> $meta
     */
    private function stringFrom(array $meta, string $key, string $default): string
    {
        $value = $meta[$key] ?? null;
        if ($value === null || !is_scalar($value)) {
            return $default;
        }

        $string = trim((string) $value);

        return $string === '' ? $default : $string;
    }

    /**
     * @param  array<string, mixed> $meta
     * @return array<string, mixed>
     */
    private function metaFrom(array $meta): array
    {
        $discovery = $meta['discovery_meta'] ?? null;
        if (!is_array($discovery)) {
            return [];
        }

        $clean = [];
        foreach ($discovery as $key => $value) {
            if (is_string($key)) {
                $clean[$key] = $value;
            }
        }

        return $clean;
    }

    /**
     * @param array<string, mixed> $meta
     */
    private function encodeMeta(array $meta): string
    {
        try {
            return json_encode($meta, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RuntimeException('The asset discovery metadata could not be encoded.', 0, $e);
        }
    }

    /**
     * The default clock, in UTC. Callers that need determinism inject the
     * sighting moment instead.
     */
    private function clock(): DateTimeImmutable
    {
        return new DateTimeImmutable('now', new DateTimeZone('UTC'));
    }
}
