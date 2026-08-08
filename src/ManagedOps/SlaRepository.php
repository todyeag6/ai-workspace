<?php

declare(strict_types=1);

namespace App\ManagedOps;

use App\Data\TenantRepository;

/**
 * Tenant-scoped, APPEND-ONLY access to the `agent_slas` ledger (P2-T4).
 *
 * Each row is one measurement of one BRD Table 4 security SLA type (patch,
 * incident_response, backup_restore_test) with a target and an observed
 * duration; the breach flag is pre-computed by SlaRecord and stored immutable.
 * Measuring again writes a NEW row. Like the evaluation and ownership ledgers,
 * the history is append-only so a past SLA result cannot be rewritten.
 *
 * AC-001 / FR-TEN-002 come from the base.
 *
 * © AI WebScapes 2026
 */
final class SlaRepository extends TenantRepository
{
    protected function table(): string
    {
        return 'agent_slas';
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
            'sla_type',
            'target_hours',
            'observed_hours',
            'breached',
            'measured_at',
        ];
    }

    public function record(int $agentId, SlaRecord $sla): int
    {
        return (int) $this->insertScoped([
            'agent_id' => $agentId,
            'sla_type' => $sla->slaType,
            'target_hours' => $sla->targetHours,
            'observed_hours' => $sla->observedHours,
            'breached' => $sla->breachedFlag(),
        ]);
    }

    /**
     * All SLA measurements for an agent, in insertion (ascending id) order.
     *
     * @return list<array<string, scalar|null>>
     */
    public function forAgent(int $agentId): array
    {
        // No ORDER BY in the predicate - TenantScope::where() appends the scope
        // predicate after $where, so a clause with ORDER BY produces dangling
        // SQL. Rows come back in ascending id order, which is what callers
        // that want "earliest first" expect.
        return $this->selectScoped('agent_id = :agent_id', ['agent_id' => $agentId]);
    }

    /**
     * Only the breached measurements - the open SLA incidents (BRD Table 4:
     * "patch SLA", "incident frequency"). Most-recent first.
     *
     * @return list<array<string, scalar|null>>
     */
    public function breaches(int $agentId): array
    {
        $rows = $this->selectScoped('agent_id = :agent_id AND breached = 1', ['agent_id' => $agentId]);

        // Sort newest-first in PHP (the base provides no ORDER BY hook).
        usort($rows, static fn (array $a, array $b): int => (int) ($b['id'] ?? 0) <=> (int) ($a['id'] ?? 0));

        return $rows;
    }
}
