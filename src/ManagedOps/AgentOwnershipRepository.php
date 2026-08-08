<?php

declare(strict_types=1);

namespace App\ManagedOps;

use App\Data\TenantRepository;

/**
 * Tenant-scoped, APPEND-ONLY access to the `agent_ownership` ledger (P2-T4).
 *
 * Like agent_evaluations, ownership is immutable once recorded: reassigning a
 * role writes a NEW row, never an UPDATE, so the accountability history is
 * tamper-evident (FR-AGENT-003's "a gate you can edit is not a gate" applies
 * equally to ownership). This class therefore exposes assign() and reads only.
 *
 * AC-001 / FR-TEN-002 come from the base, as everywhere else.
 *
 * © AI WebScapes 2026
 */
final class AgentOwnershipRepository extends TenantRepository
{
    protected function table(): string
    {
        return 'agent_ownership';
    }

    /**
     * @return list<string>
     */
    protected function columns(): array
    {
        return [
            'id',
            'tenant_id',
            'agent_id',
            'version_id',
            'business_owner',
            'technical_owner',
            'data_owner',
            'security_owner',
            'acceptance_authority',
            'update_owner',
            'backup_owner',
            'support_boundary',
            'assigned_at',
            'assigned_by',
        ];
    }

    /**
     * Records a new ownership assignment. Append-only: callers reassign by
     * calling this again, not by updating.
     */
    public function assign(AgentOwnership $ownership): int
    {
        return (int) $this->insertScoped([
            'agent_id' => $ownership->agentId,
            'version_id' => $ownership->versionId,
            'business_owner' => $ownership->roles['business_owner'] ?? '',
            'technical_owner' => $ownership->roles['technical_owner'] ?? '',
            'data_owner' => $ownership->roles['data_owner'] ?? '',
            'security_owner' => $ownership->roles['security_owner'] ?? '',
            'acceptance_authority' => $ownership->roles['acceptance_authority'] ?? '',
            'update_owner' => $ownership->roles['update_owner'] ?? '',
            'backup_owner' => $ownership->roles['backup_owner'] ?? '',
            'support_boundary' => $ownership->supportBoundary,
            'assigned_by' => $ownership->assignedBy,
        ]);
    }

    /**
     * All ownership rows for an agent, in assignment order (latest last).
     *
     * @return list<array<string, scalar|null>>
     */
    public function forAgent(int $agentId): array
    {
        // No ORDER BY in the predicate: TenantScope::where() appends the scope
        // predicate after $where, so a clause with ORDER BY would become
        // "... AND tenant_id = ?" dangling after it. Rows are inserted in
        // ascending id order, which is the assignment order we want.
        return $this->selectScoped('agent_id = :agent_id', ['agent_id' => $agentId]);
    }

    /**
     * The most recent ownership row for an agent (the currently in-force roster).
     *
     * @return array<string, scalar|null>|null
     */
    public function current(int $agentId): ?array
    {
        $rows = $this->forAgent($agentId);

        return $rows === [] ? null : $rows[count($rows) - 1];
    }
}
