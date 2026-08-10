<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Data\TenantRepository;
use DateTimeImmutable;

/**
 * The tenant-scoped, append-only occurrence history of a finding
 * (SFR-FIND-002).
 *
 * WHY A SEPARATE REPOSITORY AND NOT A METHOD ON FindingRepository.
 * App\Data\TenantRepository binds one subclass to one table - that is what
 * makes the scope predicate impossible to omit. finding_occurrences is its own
 * table, so it gets its own scoped repository, exactly as ScanRepository
 * composes ScanEventRepository and AuthorizationRepository composes
 * ScanTargetRepository.
 *
 * WHY THERE IS NO update() AND NO delete() HERE. SFR-FIND-002 requires
 * repeated evidence to update occurrence history WITHOUT destroying previous
 * state. The strongest way to guarantee that is to offer no method that could:
 * this class can add a sighting and read sightings, and that is all. A history
 * nobody can rewrite is one nobody has to be trusted not to rewrite.
 *
 * AC-001 comes from the base class: construction builds a TenantScope, and
 * every statement carries `tenant_id = :tenant` bound internally.
 *
 * © AI WebScapes 2026
 */
final class FindingOccurrenceRepository extends TenantRepository
{
    private const TIMESTAMP_FORMAT = 'Y-m-d H:i:s';

    /** finding_occurrences.note is TEXT; a runaway note is truncated, not refused. */
    private const NOTE_MAX = 2000;

    protected function table(): string
    {
        return 'finding_occurrences';
    }

    /**
     * @return list<string>
     */
    protected function columns(): array
    {
        return [
            'id',
            'tenant_id',
            'finding_id',
            'scan_id',
            'asset_id',
            'evidence_id',
            'evidence_hash',
            'observed_at',
            'status_at_observation',
            'note',
        ];
    }

    /**
     * Appends one sighting. The ONLY write path this class offers.
     *
     * The caller is responsible for having established that $findingId is
     * visible in this tenant - FindingRepository::record() does exactly that
     * before delegating here, so an occurrence can never be attached to
     * another tenant's finding.
     */
    public function add(
        int $findingId,
        int $scanId,
        DateTimeImmutable $observedAt,
        string $statusAtObservation,
        ?int $assetId = null,
        ?int $evidenceId = null,
        ?string $evidenceHash = null,
        ?string $note = null
    ): int {
        return (int) $this->insertScoped([
            'finding_id' => $findingId,
            'scan_id' => $scanId,
            'asset_id' => $assetId,
            'evidence_id' => $evidenceId,
            'evidence_hash' => $evidenceHash,
            'observed_at' => $observedAt->format(self::TIMESTAMP_FORMAT),
            'status_at_observation' => $statusAtObservation,
            'note' => $note === null ? null : mb_substr($note, 0, self::NOTE_MAX),
        ]);
    }

    /**
     * The full sighting history of one finding, oldest first - the sanctioned
     * read for a report or an operator timeline.
     *
     * @return list<FindingOccurrence>
     */
    public function forFinding(int $findingId): array
    {
        $rows = $this->selectScoped('finding_id = :finding_id', ['finding_id' => $findingId]);

        $occurrences = [];
        foreach ($rows as $row) {
            $occurrences[] = FindingOccurrence::fromRow($row);
        }

        // Sorted oldest-first here rather than in SQL: TenantRepository wraps
        // the caller predicate in parentheses (TenantScope::where), so an
        // ORDER BY inside it would become invalid SQL. Sorting in PHP keeps
        // the scoped query well-formed.
        usort(
            $occurrences,
            static fn (FindingOccurrence $a, FindingOccurrence $b): int => $a->id() <=> $b->id()
        );

        return $occurrences;
    }

    /**
     * How many times this finding has been observed.
     */
    public function countForFinding(int $findingId): int
    {
        return count($this->selectScoped('finding_id = :finding_id', ['finding_id' => $findingId]));
    }
}
