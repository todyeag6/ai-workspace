<?php

declare(strict_types=1);

namespace App\Data;

/**
 * Append-only, tenant-scoped audit records (FR-AUD-001).
 *
 * There is deliberately no update or delete method: an audit trail that the
 * application can rewrite is not evidence. Retention and redaction are an
 * operational concern handled outside the request path.
 *
 * © AI WebScapes 2026
 */
final class AuditLogRepository extends TenantRepository
{
    protected function table(): string
    {
        return 'audit_log';
    }

    /**
     * @return list<string>
     */
    protected function columns(): array
    {
        return [
            'id',
            'tenant_id',
            'actor_user_id',
            'event',
            'outcome',
            'object_type',
            'object_id',
            'detail',
            'created_at',
        ];
    }

    /**
     * The tenant is NOT a parameter here - insertScoped() forces it from the
     * repository's own scope, so an audit record cannot be filed against
     * another tenant even by a caller that wants to.
     */
    public function append(
        ?int $actorUserId,
        string $event,
        string $outcome,
        ?string $objectType,
        ?string $objectId,
        ?string $detail
    ): string {
        return $this->insertScoped([
            'actor_user_id' => $actorUserId,
            'event' => $event,
            'outcome' => $outcome,
            'object_type' => $objectType,
            'object_id' => $objectId,
            'detail' => $detail,
        ]);
    }
}
