<?php

declare(strict_types=1);

namespace App\Agents;

use App\Data\TenantRepository;

/**
 * Tenant-scoped, APPEND-ONLY access to the `agent_versions` table.
 *
 * FR-AGENT-003 says a prompt or config change produces a new version rather
 * than editing the old one. That is enforced here by omission, which is the
 * only enforcement that survives a future contributor: this class exposes
 * append() and reads, and NOTHING else. updateScoped() and deleteScoped()
 * exist on the base but are `protected`, so no caller outside this class can
 * reach them, and this class declares no method that calls them. There is
 * literally no public operation that can alter a stored prompt, config or
 * allow-list.
 *
 * AC-001 comes from the base in the same way it does for AgentRepository: the
 * tenant column is on this table too (see migrations/002_agents.sql for why it
 * is carried denormalised rather than joined through agents).
 *
 * © AI WebScapes 2026
 */
final class AgentVersionRepository extends TenantRepository
{
    protected function table(): string
    {
        return 'agent_versions';
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
            'version_number',
            'system_prompt',
            'model_config',
            'allowed_tools',
            'created_at',
        ];
    }

    /**
     * @param  array<string, scalar|null> $values
     * @return int The new version id.
     */
    public function append(array $values): int
    {
        return (int) $this->insertScoped($values);
    }

    /**
     * Every version of one agent, in insertion order as the database returns
     * it. Ordering is applied by the caller (App\Agents\AgentRegistry) rather
     * than in SQL because the base class deliberately offers no ORDER BY hook:
     * a caller-supplied fragment is parenthesised into the WHERE clause, so
     * `ORDER BY` cannot be smuggled in there - and that restriction is what
     * keeps the tenant predicate un-widenable. Version counts per agent are
     * small and bounded by human edits, so sorting in PHP costs nothing real.
     *
     * @return list<array<string, scalar|null>>
     */
    public function forAgent(int $agentId): array
    {
        return $this->selectScoped('agent_id = :agent_id', ['agent_id' => $agentId]);
    }

    /**
     * @return array<string, scalar|null>|null
     */
    public function findVersion(int $versionId): ?array
    {
        $rows = $this->selectScoped('id = :id', ['id' => $versionId]);

        return $rows[0] ?? null;
    }
}
