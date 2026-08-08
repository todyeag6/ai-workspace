<?php

declare(strict_types=1);

namespace App\Agents;

use App\Data\TenantRepository;
use App\Eval\EvalResult;

/**
 * Tenant-scoped, APPEND-ONLY access to the `agent_evaluations` ledger (P2-T1).
 *
 * FR-AGENT-003's gate verdict must be durable and non-retroactive, so a
 * recorded pass/fail cannot be edited after the fact - this class exposes
 * append() and reads only, exactly like AgentVersionRepository. The
 * immutability is the governance property: a release gate whose record is
 * mutable is not a gate.
 *
 * AC-001 comes from the base, as everywhere else.
 *
 * © AI WebScapes 2026
 */
final class AgentEvaluationRepository extends TenantRepository
{
    protected function table(): string
    {
        return 'agent_evaluations';
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
            'run_at',
            'passed',
            'cases_run',
            'failed_kpis',
            'thresholds_json',
        ];
    }

    /**
     * @param list<string> $failedKpis
     * @param array<string, mixed> $thresholds
     */
    public function record(
        int $agentId,
        int $versionId,
        bool $passed,
        int $casesRun,
        array $failedKpis,
        array $thresholds
    ): int {
        return (int) $this->insertScoped([
            'agent_id' => $agentId,
            'version_id' => $versionId,
            'passed' => $passed ? 1 : 0,
            'cases_run' => $casesRun,
            'failed_kpis' => implode(',', $failedKpis),
            'thresholds_json' => (string) json_encode($thresholds, JSON_UNESCAPED_SLASHES),
        ]);
    }

    /**
     * Every evaluation of one agent, in insertion order.
     *
     * @return list<array<string, scalar|null>>
     */
    public function forAgent(int $agentId): array
    {
        return $this->selectScoped('agent_id = :agent_id', ['agent_id' => $agentId]);
    }
}
