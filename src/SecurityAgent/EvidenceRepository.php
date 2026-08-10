<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Data\TenantRepository;
use JsonException;
use RuntimeException;

/**
 * Tenant-scoped persistence for scan evidence (SFR-EVID-001, SFR-EVID-002,
 * SFR-SELF-004).
 *
 * WHY A SEPARATE REPOSITORY AND NOT A METHOD ON ScanRepository. App\Data\
 * TenantRepository binds one subclass to one table - that is what makes the
 * scope predicate impossible to omit. Evidence is its own child table with its
 * own shape (JSON columns, a content hash, redaction metadata), so it gets its
 * own scoped repository exactly as AssetRepository / ScanEventRepository did.
 *
 * WHY THE HASH AND REDACTION FIELDS ARE WRITTEN BY THE CALLER. The component
 * that DECIDES whether evidence is safe to store is EvidenceProcessor; this one
 * only MOVES ROWS. If the repository recomputed the hash or re-ran redaction it
 * would be the judge as well as the scribe, which is the decide-vs-act split
 * ScopeManager / SafetyMonitor established for this module. So store() accepts
 * an already-canonicalized Evidence and writes exactly what it was given.
 *
 * WHY the content hash is indexed by (tenant_id, content_hash). The P3-T4 exit
 * gate requires repeated evidence to update occurrence history WITHOUT
 * destroying previous state (SFR-FIND-002, and the SFR-EVID-001 hash supports
 * it). An index on the hash lets findByHash() locate a prior observation fast,
 * so the caller can attach a new occurrence to the existing record rather than
 * duplicating it - history is preserved because the old row is never deleted.
 *
 * AC-001 comes from the base class: construction builds a TenantScope, and
 * every statement carries `tenant_id = :tenant` bound internally.
 *
 * © AI WebScapes 2026
 */
final class EvidenceRepository extends TenantRepository
{
    protected function table(): string
    {
        return 'security_evidence';
    }

    /**
     * @return list<string>
     */
    protected function columns(): array
    {
        return [
            'id',
            'tenant_id',
            'scan_id',
            'asset_id',
            'scanner',
            'scanner_version',
            'target',
            'captured_at',
            'request_category',
            'response_metadata',
            'reproduction',
            'content_hash',
            'redaction_fingerprints',
            'redacted_at',
        ];
    }

    /**
     * Persists one evidence item and returns its generated id.
     *
     * The hash and redaction metadata are already computed by EvidenceProcessor;
     * this repository writes them verbatim (decide-not-act split).
     */
    public function store(Evidence $evidence): int
    {
        if ($evidence->tenantId() !== $this->tenantId()) {
            // The base class makes this near-impossible, but a caller building
            // an Evidence in the wrong tenant must not be able to persist it
            // here - that would be a cross-tenant write AC-001 forbids.
            throw new RuntimeException(
                'The evidence belongs to a different tenant than this repository.'
            );
        }

        return (int) $this->insertScoped([
            'scan_id' => $evidence->scanId(),
            'asset_id' => $evidence->assetId(),
            'scanner' => $evidence->scanner(),
            'scanner_version' => $evidence->scannerVersion(),
            'target' => $evidence->target(),
            'captured_at' => $evidence->capturedAt()->format('Y-m-d H:i:s'),
            'request_category' => $evidence->requestCategory(),
            'response_metadata' => $this->encodeJson($evidence->responseMetadata()),
            'reproduction' => $this->encodeJsonNullable($evidence->reproduction()),
            'content_hash' => $evidence->contentHash(),
            'redaction_fingerprints' => $this->encodeKinds($evidence->redactionKinds()),
            'redacted_at' => $evidence->redactedAt()?->format('Y-m-d H:i:s'),
        ]);
    }

    /**
     * Null both when the evidence does not exist and when it belongs to another
     * tenant - deliberately indistinguishable (AC-001).
     */
    public function findById(int $id): ?Evidence
    {
        $rows = $this->selectScoped('id = :id', ['id' => $id]);
        if ($rows === []) {
            return null;
        }

        return Evidence::fromRow($rows[0]);
    }

    /**
     * All evidence for one scan, oldest first - the sanctioned read for a
     * report or an operator view.
     *
     * @return list<Evidence>
     */
    public function forScan(int $scanId): array
    {
        $rows = $this->selectScoped('scan_id = :scan_id', ['scan_id' => $scanId]);

        $items = [];
        foreach ($rows as $row) {
            $items[] = Evidence::fromRow($row);
        }

        // Sorted oldest-first here rather than in SQL: TenantRepository wraps
        // the caller predicate in parentheses (TenantScope::where), so an
        // ORDER BY inside it would become invalid SQL. Sorting in PHP keeps
        // the scoped query well-formed.
        usort($items, static fn (Evidence $a, Evidence $b): int => $a->id() <=> $b->id());

        return $items;
    }

    /**
     * Prior observations of the same canonical content within this tenant
     * (SFR-FIND-002 / SFR-EVID-001 hash support). Returns the existing rows so
     * the caller can attach a NEW occurrence rather than overwrite history.
     *
     * @return list<Evidence>
     */
    public function findByHash(string $contentHash): array
    {
        $hash = trim($contentHash);
        if ($hash === '') {
            throw new RuntimeException('A content hash lookup needs a non-empty hash.');
        }

        $rows = $this->selectScoped('content_hash = :hash', ['hash' => $hash]);

        $items = [];
        foreach ($rows as $row) {
            $items[] = Evidence::fromRow($row);
        }

        usort($items, static fn (Evidence $a, Evidence $b): int => $a->id() <=> $b->id());

        return $items;
    }

    /**
     * @param array<array-key, mixed> $value
     */
    private function encodeJson(array $value): string
    {
        try {
            return json_encode($value, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RuntimeException('The evidence response metadata could not be encoded.', 0, $e);
        }
    }

    /**
     * @param array<string, mixed>|null $value
     */
    private function encodeJsonNullable(?array $value): ?string
    {
        if ($value === null) {
            return null;
        }

        return $this->encodeJson($value);
    }

    /**
     * @param list<string> $kinds
     */
    private function encodeKinds(array $kinds): ?string
    {
        if ($kinds === []) {
            return null;
        }

        return $this->encodeJson($kinds);
    }
}
