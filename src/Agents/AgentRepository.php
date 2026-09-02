<?php

declare(strict_types=1);

namespace App\Agents;

use App\Data\TenantRepository;

/**
 * Tenant-scoped access to the `agents` table.
 *
 * AC-001 is inherited, not re-implemented: extending App\Data\TenantRepository
 * means this class cannot be constructed without a tenant, cannot see the PDO
 * handle (it is private in the base), and cannot emit a statement without
 * `tenant_id = :tenant` in it. There is therefore no code path here - present
 * or future - through which an agent belonging to another tenant becomes
 * readable or writable, which is exactly what the P1-T3 base was built for.
 *
 * The class holds no policy. Whether an agent MAY be activated is
 * App\Agents\AgentRegistry's decision (FR-AGENT-002); this class only knows
 * how to persist the outcome of that decision.
 *
 * © AI WebScapes 2026
 */
final class AgentRepository extends TenantRepository
{
    protected function table(): string
    {
        return 'agents';
    }

    /**
     * @return list<string>
     */
    protected function columns(): array
    {
        return [
            'id',
            'tenant_id',
            'name',
            'owner',
            'purpose',
            'risk_class',
            'data_classes',
            'deployment_location',
            'status',
            'active_version_id',
            'retirement_date',
            'created_at',
            'updated_at',
        ];
    }

    /**
     * @param  array<string, scalar|null> $values
     * @return int The new agent id.
     */
    public function add(array $values): int
    {
        return (int) $this->insertScoped($values);
    }

    /**
     * @return array<string, scalar|null>|null Null when the agent does not
     *         exist OR belongs to another tenant - deliberately the same
     *         answer (AC-001).
     */
    public function findAgent(int $agentId): ?array
    {
        $rows = $this->selectScoped('id = :id', ['id' => $agentId]);

        return $rows[0] ?? null;
    }

    /**
     * Every active agent for this tenant, in no particular order.
     *
     * @return list<array<string, scalar|null>>
     */
    public function listActive(): array
    {
        return $this->selectScoped('status = :status', ['status' => AgentRegistry::STATUS_ACTIVE]);
    }

    /**
     * @return int Affected rows: 0 when the agent is outside this tenant, so a
     *         cross-tenant write is refused by the database rather than by an
     *         application check that could be skipped.
     */
    public function setStatus(int $agentId, string $status): int
    {
        return $this->updateScoped(['status' => $status], 'id = :id', ['id' => $agentId]);
    }

    public function retire(int $agentId, string $retirementDate): int
    {
        return $this->updateScoped(
            ['status' => 'retired', 'retirement_date' => $retirementDate],
            'id = :id',
            ['id' => $agentId]
        );
    }

    /**
     * Moves the agent's pointer onto a version row (FR-AGENT-003).
     *
     * Note what this does NOT do: it never rewrites a version. The pointer
     * moves, the pointed-at rows stay exactly as they were written.
     */
    public function pointAtVersion(int $agentId, int $versionId): int
    {
        return $this->updateScoped(
            ['active_version_id' => $versionId],
            'id = :id',
            ['id' => $agentId]
        );
    }
}
