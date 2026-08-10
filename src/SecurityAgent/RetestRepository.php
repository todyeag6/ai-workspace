<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Data\TenantRepository;
use DateTimeImmutable;

/**
 * The tenant-scoped, append-only retest log (SFR-RETEST-001).
 *
 * WHY A SEPARATE REPOSITORY. App\Data\TenantRepository binds one subclass to
 * one table — that is what makes the scope predicate impossible to omit.
 * `retests` is its own table, so it gets its own scoped repository, exactly as
 * FindingRepository composes FindingOccurrenceRepository.
 *
 * WHY THERE IS NO update() AND NO delete() HERE. A retest result is a
 * historical fact: on this date, this person re-ran this profile and this is
 * what happened. Offering an edit path would let a failed verification be
 * quietly turned into a passing one — which is precisely the closure fraud
 * FRD section 7 exists to prevent, since a passing retest is what unlocks
 * closure. A history nobody can rewrite is one nobody has to be trusted not to
 * rewrite.
 *
 * AC-001 comes from the base class: construction builds a TenantScope, and
 * every statement carries `tenant_id = :tenant` bound internally.
 *
 * © AI WebScapes 2026
 */
final class RetestRepository extends TenantRepository
{
    private const TIMESTAMP_FORMAT = 'Y-m-d H:i:s';

    /** retests.note is TEXT; a runaway note is truncated, not refused. */
    private const NOTE_MAX = 2000;

    protected function table(): string
    {
        return 'retests';
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
            'remediation_id',
            'scan_profile_id',
            'profile_version',
            'scan_id',
            'result',
            'evidence_id',
            'evidence_hash',
            'performed_by',
            'performed_at',
            'note',
        ];
    }

    /**
     * Appends one retest result. The ONLY write path this class offers.
     *
     * The Retest value object is constructed FIRST, before any SQL runs, so
     * its invariants — the three SFR-RETEST-001 links, the named human, and
     * the FRD section 7 "a pass must carry evidence" rule — are enforced
     * before a row can exist. An unevidenced pass never reaches the database.
     *
     * The caller is responsible for having established that $findingId and
     * $remediationId are visible in this tenant; RemediationRepository does
     * exactly that before delegating here.
     */
    public function record(
        int $findingId,
        int $remediationId,
        int $scanProfileId,
        int $profileVersion,
        string $result,
        string $performedBy,
        DateTimeImmutable $performedAt,
        ?int $scanId = null,
        ?int $evidenceId = null,
        ?string $evidenceHash = null,
        ?string $note = null
    ): int {
        // Validation by construction: throws before the INSERT.
        new Retest(
            $this->tenantId(),
            // A placeholder id purely to satisfy the value object's
            // positive-id invariant; the real one is assigned by the database
            // below. The row this validates is otherwise identical.
            1,
            $findingId,
            $remediationId,
            $scanProfileId,
            $profileVersion,
            $result,
            $performedBy,
            $performedAt,
            $scanId,
            $evidenceId,
            $evidenceHash,
            $note
        );

        return (int) $this->insertScoped([
            'finding_id' => $findingId,
            'remediation_id' => $remediationId,
            'scan_profile_id' => $scanProfileId,
            'profile_version' => $profileVersion,
            'scan_id' => $scanId,
            'result' => $result,
            'evidence_id' => $evidenceId,
            'evidence_hash' => $evidenceHash,
            'performed_by' => trim($performedBy),
            'performed_at' => $performedAt->format(self::TIMESTAMP_FORMAT),
            'note' => $note === null ? null : mb_substr($note, 0, self::NOTE_MAX),
        ]);
    }

    /**
     * Every retest recorded against one remediation, oldest first — the input
     * to the FRD section 7 closure decision.
     *
     * @return list<Retest>
     */
    public function forRemediation(int $remediationId): array
    {
        $rows = $this->selectScoped(
            'remediation_id = :remediation_id',
            ['remediation_id' => $remediationId]
        );

        return $this->hydrate($rows);
    }

    /**
     * Every retest recorded against one finding, oldest first.
     *
     * @return list<Retest>
     */
    public function forFinding(int $findingId): array
    {
        $rows = $this->selectScoped('finding_id = :finding_id', ['finding_id' => $findingId]);

        return $this->hydrate($rows);
    }

    /**
     * @param list<array<string, scalar|null>> $rows
     *
     * @return list<Retest>
     */
    private function hydrate(array $rows): array
    {
        $retests = [];
        foreach ($rows as $row) {
            $retests[] = Retest::fromRow($row);
        }

        // Sorted here rather than in SQL: TenantRepository wraps the caller
        // predicate in parentheses (TenantScope::where), so an ORDER BY inside
        // it would be invalid SQL.
        usort($retests, static fn (Retest $a, Retest $b): int => $a->id() <=> $b->id());

        return $retests;
    }
}
