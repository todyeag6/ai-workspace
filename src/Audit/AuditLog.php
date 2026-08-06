<?php

declare(strict_types=1);

namespace App\Audit;

use App\Data\AuditLogRepository;
use PDO;

/**
 * The audit trail (FR-AUD-001): who did what, in which tenant, and how it
 * turned out.
 *
 * WHY THIS TAKES A PDO AND BUILDS A REPOSITORY PER CALL. Audit records are
 * tenant-scoped rows, and App\Data\AuditLogRepository - like every repository
 * here - cannot exist without a tenant. But the tenant of an audit record is
 * only known at the moment of the event (it comes from the authenticated
 * subject), so a single long-lived repository would have to be either unscoped
 * or wrong. Constructing one per event keeps the scope structural: the tenant
 * on the row is forced by the repository, never passed as a column.
 *
 * FAILURES ARE AUDITED, NOT ONLY SUCCESSES. A trail that records only what
 * worked cannot answer the question an incident actually asks - what was
 * TRIED. Hence loginFailed() and denied().
 *
 * © AI WebScapes 2026
 */
final class AuditLog
{
    public const EVENT_LOGIN = 'auth.login';

    public const OUTCOME_SUCCESS = 'success';
    public const OUTCOME_FAILURE = 'failure';
    public const OUTCOME_DENIED = 'denied';

    /**
     * audit_log.detail is VARCHAR(255). Truncating here rather than letting
     * MySQL do it keeps the behaviour identical under STRICT_TRANS_TABLES,
     * where an over-long value is an error and would turn a denial into a
     * 500 - i.e. the audit write would break the very request it is recording.
     */
    private const DETAIL_MAX = 255;

    public function __construct(private PDO $pdo)
    {
    }

    public function loginSucceeded(int $tenantId, int $userId): void
    {
        $this->record($tenantId, $userId, self::EVENT_LOGIN, self::OUTCOME_SUCCESS, null, null, 'password');
    }

    /**
     * $actorUserId is null when the presented identity did not resolve - there
     * is no user to attribute the attempt to, and inventing one would be a lie
     * in the trail.
     */
    public function loginFailed(int $tenantId, ?int $actorUserId, string $detail): void
    {
        $this->record($tenantId, $actorUserId, self::EVENT_LOGIN, self::OUTCOME_FAILURE, null, null, $detail);
    }

    public function denied(
        int $tenantId,
        ?int $actorUserId,
        string $event,
        string $action,
        ?string $objectId,
        string $reason
    ): void {
        $this->record(
            $tenantId,
            $actorUserId,
            $event,
            self::OUTCOME_DENIED,
            null,
            $objectId,
            sprintf('%s: %s', $action, $reason)
        );
    }

    public function record(
        int $tenantId,
        ?int $actorUserId,
        string $event,
        string $outcome,
        ?string $objectType,
        ?string $objectId,
        ?string $detail
    ): void {
        (new AuditLogRepository($this->pdo, $tenantId))->append(
            $actorUserId,
            $event,
            $outcome,
            $objectType,
            $objectId,
            $detail === null ? null : mb_substr($detail, 0, self::DETAIL_MAX)
        );
    }
}
