<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Tenancy\TenantScope;
use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;

/**
 * One retest: the verification that a fix actually worked (FRD section 4
 * `retests` — "profile, result, linked finding"; SFR-RETEST-001).
 *
 * An immutable value object, never a live handle.
 *
 * SFR-RETEST-001 VERBATIM: "Retests shall use a defined subset/profile and
 * link results to the original finding and remediation."
 * ---------------------------------------------------------------------------
 * Three obligations, three non-nullable fields: scanProfileId (the defined
 * profile), findingId (the original finding) and remediationId (the
 * remediation). None has a default, so a retest that fails to link cannot be
 * constructed.
 *
 * THIS OBJECT IS THE CLOSURE EVIDENCE (FRD section 7)
 * ----------------------------------------------------
 * The acceptance test reads: "Closure requires passing evidence linked to
 * remediation." Three conjunctions — passing, evidence, and linked. A PASSING
 * retest therefore REFUSES to exist without an evidence reference: see the
 * constructor guard. That is the difference between a system where closure is
 * proven and one where closure is merely claimed by whoever wanted it closed.
 *
 * A fail or an inconclusive result may carry no evidence, because there may
 * genuinely be no artefact to store — but neither of those can close anything,
 * so the guarantee is unaffected.
 *
 * WHY 'inconclusive' EXISTS AS A THIRD RESULT
 * --------------------------------------------
 * SFR-SCAN-003: "Tool failure shall not be interpreted as target
 * vulnerability; failure state and evidence shall be recorded." A retest whose
 * scanner crashed has learned nothing about the target. With only pass/fail
 * available, that run would have to be recorded as a fail — asserting the fix
 * did not work when nobody checked — or quietly discarded. Both are lies of a
 * different sign. `inconclusive` is the honest third answer, and it closes
 * nothing.
 *
 * NO CLOCK OF ITS OWN. The moment of the retest is passed in by the caller.
 *
 * © AI WebScapes 2026
 */
final class Retest
{
    private const TIMESTAMP_FORMAT = 'Y-m-d H:i:s';

    /** The finding could not be reproduced: the fix holds. The only closing result. */
    public const RESULT_PASS = 'pass';

    /** The finding is still reproducible: the fix did not work. */
    public const RESULT_FAIL = 'fail';

    /**
     * The retest could not determine anything — a tool failure, an
     * unreachable target, an aborted run (SFR-SCAN-003).
     */
    public const RESULT_INCONCLUSIVE = 'inconclusive';

    /** @var list<string> */
    public const RESULTS = [
        self::RESULT_PASS,
        self::RESULT_FAIL,
        self::RESULT_INCONCLUSIVE,
    ];

    public function __construct(
        private readonly int $tenantId,
        private readonly int $id,
        private readonly int $findingId,
        private readonly int $remediationId,
        private readonly int $scanProfileId,
        private readonly int $profileVersion,
        private readonly string $result,
        private readonly string $performedBy,
        private readonly DateTimeImmutable $performedAt,
        private readonly ?int $scanId = null,
        private readonly ?int $evidenceId = null,
        private readonly ?string $evidenceHash = null,
        private readonly ?string $note = null,
    ) {
        if ($tenantId <= 0) {
            throw new InvalidArgumentException(
                'A retest must belong to a real tenant; 0 or negative is not a tenant (AC-001).'
            );
        }

        // SFR-RETEST-001's three links, each refused when absent.
        if ($findingId <= 0) {
            throw new InvalidArgumentException(
                'A retest must link to the original finding (SFR-RETEST-001).'
            );
        }

        if ($remediationId <= 0) {
            throw new InvalidArgumentException(
                'A retest must link to the remediation it verifies (SFR-RETEST-001); an '
                . 'unlinked retest cannot close anything (FRD section 7).'
            );
        }

        if ($scanProfileId <= 0) {
            throw new InvalidArgumentException(
                'A retest must name the defined subset/profile it ran (SFR-RETEST-001).'
            );
        }

        if ($profileVersion <= 0) {
            throw new InvalidArgumentException(
                'A retest must pin the profile VERSION it ran under; profiles are versioned and '
                . 'immutable once used (SFR-SCAN-001).'
            );
        }

        self::assertOneOf($result, self::RESULTS, 'result');

        if (trim($performedBy) === '') {
            // A retest asserts that something is fixed. SFR-AI-001 reserves
            // that class of judgement for a named person.
            throw new InvalidArgumentException(
                'A retest must name the human who performed it (SFR-AI-001, SFR-AUD-001).'
            );
        }

        // THE LOAD-BEARING GUARD (FRD section 7). A pass is the only result
        // that can close a finding, so a pass without evidence is refused at
        // construction — before it can reach a database, a report, or a
        // closure decision.
        if ($result === self::RESULT_PASS && $evidenceId === null && $evidenceHash === null) {
            throw new InvalidArgumentException(
                'A passing retest must carry evidence: closure requires PASSING EVIDENCE linked '
                . 'to remediation (FRD section 7 acceptance test, SFR-RETEST-001). A pass with '
                . 'no artefact is a claim, not a verification.'
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
            throw new InvalidArgumentException('A retest row must carry a positive id.');
        }

        return new self(
            $tenant->id(),
            $id,
            self::intOf($row['finding_id'] ?? null),
            self::intOf($row['remediation_id'] ?? null),
            self::intOf($row['scan_profile_id'] ?? null),
            max(1, self::intOf($row['profile_version'] ?? null)),
            self::stringOf($row['result'] ?? null, self::RESULT_INCONCLUSIVE),
            self::stringOf($row['performed_by'] ?? null, ''),
            self::timeOf($row['performed_at'] ?? null, 'performed_at'),
            self::intOrNull($row['scan_id'] ?? null),
            self::intOrNull($row['evidence_id'] ?? null),
            self::stringOrNull($row['evidence_hash'] ?? null),
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

    public function remediationId(): int
    {
        return $this->remediationId;
    }

    public function scanProfileId(): int
    {
        return $this->scanProfileId;
    }

    public function profileVersion(): int
    {
        return $this->profileVersion;
    }

    public function result(): string
    {
        return $this->result;
    }

    public function performedBy(): string
    {
        return $this->performedBy;
    }

    public function performedAt(): DateTimeImmutable
    {
        return $this->performedAt;
    }

    public function scanId(): ?int
    {
        return $this->scanId;
    }

    public function evidenceId(): ?int
    {
        return $this->evidenceId;
    }

    public function evidenceHash(): ?string
    {
        return $this->evidenceHash;
    }

    public function note(): ?string
    {
        return $this->note;
    }

    /**
     * Whether this retest carries the artefact that makes its result checkable
     * by someone who was not there (SFR-EVID-001).
     */
    public function hasEvidence(): bool
    {
        return $this->evidenceId !== null || $this->evidenceHash !== null;
    }

    /**
     * Whether this retest is capable of closing the finding it verifies.
     *
     * BOTH clauses of FRD section 7 in one question: the result must be a pass
     * AND it must carry evidence. RemediationTracker asks exactly this, so the
     * closure rule is stated once and read everywhere rather than reimplemented
     * by each caller.
     */
    public function closesFinding(): bool
    {
        return $this->result === self::RESULT_PASS && $this->hasEvidence();
    }

    /**
     * The sanctioned projection for the retest report the BRD names as a
     * deliverable (BRD section 6, SFR-REPORT-001).
     *
     * @return array{
     *     tenant_id: int,
     *     id: int,
     *     finding_id: int,
     *     remediation_id: int,
     *     scan_profile_id: int,
     *     profile_version: int,
     *     scan_id: int|null,
     *     result: string,
     *     evidence_id: int|null,
     *     evidence_hash: string|null,
     *     performed_by: string,
     *     performed_at: string,
     *     note: string|null
     * }
     */
    public function toReportArray(): array
    {
        return [
            'tenant_id' => $this->tenantId,
            'id' => $this->id,
            'finding_id' => $this->findingId,
            'remediation_id' => $this->remediationId,
            'scan_profile_id' => $this->scanProfileId,
            'profile_version' => $this->profileVersion,
            'scan_id' => $this->scanId,
            'result' => $this->result,
            'evidence_id' => $this->evidenceId,
            'evidence_hash' => $this->evidenceHash,
            'performed_by' => $this->performedBy,
            'performed_at' => $this->performedAt->format(self::TIMESTAMP_FORMAT),
            'note' => $this->note,
        ];
    }

    /**
     * @param list<string> $allowed
     */
    private static function assertOneOf(string $value, array $allowed, string $field): void
    {
        if (!in_array($value, $allowed, true)) {
            throw new InvalidArgumentException(sprintf(
                'Unknown retest %s "%s". It must be one of: %s (allowlist, AC-002).',
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
            throw new InvalidArgumentException(sprintf('A retest row must carry %s.', $field));
        }

        $parsed = DateTimeImmutable::createFromFormat(
            self::TIMESTAMP_FORMAT,
            (string) $value,
            new DateTimeZone('UTC')
        );

        if ($parsed === false) {
            throw new InvalidArgumentException(sprintf(
                'Unreadable retest timestamp "%s" for %s; expected %s in UTC.',
                (string) $value,
                $field,
                self::TIMESTAMP_FORMAT
            ));
        }

        return $parsed;
    }
}
