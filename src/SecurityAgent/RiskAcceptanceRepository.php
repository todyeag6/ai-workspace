<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Data\TenantRepository;
use DateTimeImmutable;

/**
 * The tenant-scoped register of formally accepted risks (SBR-5.3, FRD section
 * 4 `risk_acceptances`).
 *
 * WHY A SEPARATE REPOSITORY. Same reason as RetestRepository:
 * App\Data\TenantRepository binds one subclass to one table, so a second table
 * gets a second scoped repository, composed by RemediationRepository rather
 * than injected into it.
 *
 * WHY AN ACCEPTANCE IS NEVER DELETED, ONLY REVOKED. SBR-5.3 makes an
 * acceptance a named decision with a rationale. Deleting one would erase the
 * evidence that somebody chose to accept a risk — exactly the accountability
 * the requirement creates. revoke() therefore writes a status, a revoker and a
 * reason; the original approver, rationale and control stay readable forever.
 *
 * WHAT THIS CLASS DELIBERATELY CANNOT DO: change the approver, the rationale,
 * the compensating control or the expiry of an existing acceptance. Those are
 * the terms of the decision; altering them after the fact would make the
 * register unreliable. A different decision is a NEW acceptance, which is why
 * the schema has no unique key on finding_id.
 *
 * © AI WebScapes 2026
 */
final class RiskAcceptanceRepository extends TenantRepository
{
    private const TIMESTAMP_FORMAT = 'Y-m-d H:i:s';

    protected function table(): string
    {
        return 'risk_acceptances';
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
            'approver',
            'rationale',
            'compensating_control',
            'review_at',
            'expires_at',
            'status',
            'revoked_by',
            'revoked_at',
            'revocation_reason',
            'created_at',
        ];
    }

    /**
     * Records one risk acceptance.
     *
     * The value object is constructed first, so SBR-5.3's five mandatory
     * elements — approver, rationale, compensating control, review date,
     * expiry — are all enforced before a row can exist. An acceptance missing
     * any of them never reaches the database.
     */
    public function grant(
        int $findingId,
        string $approver,
        string $rationale,
        string $compensatingControl,
        DateTimeImmutable $reviewAt,
        DateTimeImmutable $expiresAt,
        DateTimeImmutable $grantedAt,
        int $maxRationaleChars,
        int $maxControlChars
    ): int {
        $trimmedRationale = mb_substr(trim($rationale), 0, $maxRationaleChars);
        $trimmedControl = mb_substr(trim($compensatingControl), 0, $maxControlChars);

        // Validation by construction: throws before the INSERT.
        new RiskAcceptance(
            $this->tenantId(),
            1,
            $findingId,
            $approver,
            $trimmedRationale,
            $trimmedControl,
            $reviewAt,
            $expiresAt,
            RiskAcceptance::STATUS_ACTIVE,
            $grantedAt
        );

        return (int) $this->insertScoped([
            'finding_id' => $findingId,
            'approver' => trim($approver),
            'rationale' => $trimmedRationale,
            'compensating_control' => $trimmedControl,
            'review_at' => $reviewAt->format(self::TIMESTAMP_FORMAT),
            'expires_at' => $expiresAt->format(self::TIMESTAMP_FORMAT),
            'status' => RiskAcceptance::STATUS_ACTIVE,
            'created_at' => $grantedAt->format(self::TIMESTAMP_FORMAT),
        ]);
    }

    /**
     * Withdraws an acceptance before its expiry. The terms of the original
     * decision are left intact — only the status and the revocation fields
     * are written.
     *
     * @return bool False when no such acceptance is visible in this tenant.
     */
    public function revoke(
        int $id,
        string $revokedBy,
        string $reason,
        DateTimeImmutable $revokedAt
    ): bool {
        $affected = $this->updateScoped(
            [
                'status' => RiskAcceptance::STATUS_REVOKED,
                'revoked_by' => trim($revokedBy),
                'revoked_at' => $revokedAt->format(self::TIMESTAMP_FORMAT),
                'revocation_reason' => trim($reason) === '' ? null : trim($reason),
            ],
            'id = :id',
            ['id' => $id]
        );

        return $affected > 0;
    }

    /**
     * Null both when the acceptance does not exist and when it belongs to
     * another tenant — deliberately indistinguishable (AC-001).
     */
    public function findById(int $id): ?RiskAcceptance
    {
        $rows = $this->selectScoped('id = :id', ['id' => $id]);
        if ($rows === []) {
            return null;
        }

        return RiskAcceptance::fromRow($rows[0]);
    }

    /**
     * Every acceptance ever granted against one finding, oldest first —
     * including expired and revoked ones, because the register is a history.
     *
     * @return list<RiskAcceptance>
     */
    public function forFinding(int $findingId): array
    {
        $rows = $this->selectScoped('finding_id = :finding_id', ['finding_id' => $findingId]);

        return $this->hydrate($rows);
    }

    /**
     * Every acceptance in the tenant, oldest first — the exception / risk
     * acceptance register the BRD names as a deliverable (BRD section 6).
     *
     * @return list<RiskAcceptance>
     */
    public function all(): array
    {
        return $this->hydrate($this->selectScoped());
    }

    /**
     * @param list<array<string, scalar|null>> $rows
     *
     * @return list<RiskAcceptance>
     */
    private function hydrate(array $rows): array
    {
        $acceptances = [];
        foreach ($rows as $row) {
            $acceptances[] = RiskAcceptance::fromRow($row);
        }

        // Sorted in PHP: selectScoped() parenthesises the predicate, so an
        // ORDER BY inside it would be invalid SQL.
        usort(
            $acceptances,
            static fn (RiskAcceptance $a, RiskAcceptance $b): int => $a->id() <=> $b->id()
        );

        return $acceptances;
    }
}
