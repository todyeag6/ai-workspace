<?php

declare(strict_types=1);

namespace App\VerticalOffering;

use App\Data\TenantRepository;

/**
 * Tenant-scoped, append-only-ish access to the `launched_offerings` ledger
 * (P2-T5).
 *
 * One row per successful launch of a template within a tenant. `activated`
 * records whether the eval gate passed and the agents were switched on, or the
 * offering was recorded DISABLED because the gate refused it. The row is the
 * audit trail of "was this vertical package ever launched here, and did it go
 * live" — independent of the individual agents' current status.
 *
 * AC-001 / FR-TEN-002 come from the base, as everywhere else. A UNIQUE key on
 * (tenant_id, template_name) in the migration lets a re-launch be detected by
 * the caller (the base turns a collision into 0 affected rows), so we do not
 * silently duplicate an offering.
 *
 * © AI WebScapes 2026
 */
final class LaunchedOfferingRepository extends TenantRepository
{
    protected function table(): string
    {
        return 'launched_offerings';
    }

    /**
     * @return list<string>
     */
    protected function columns(): array
    {
        return [
            'id',
            'tenant_id',
            'template_name',
            'agent_count',
            'activated',
            'failed_kpis',
            'launched_by',
            'launched_at',
        ];
    }

    /**
     * @param list<string> $failedKpis
     */
    public function record(string $templateName, int $agentCount, bool $activated, array $failedKpis, string $launchedBy): int
    {
        return (int) $this->insertScoped([
            'template_name' => $templateName,
            'agent_count' => $agentCount,
            'activated' => $activated ? 1 : 0,
            'failed_kpis' => implode(',', $failedKpis),
            'launched_by' => $launchedBy,
        ]);
    }

    /**
     * The launched-offering row for a template name, or null when this tenant
     * never launched it (AC-001: indistinguishable from "launched by another
     * tenant").
     *
     * @return array<string, scalar|null>|null
     */
    public function find(string $templateName): ?array
    {
        $rows = $this->selectScoped('template_name = :template_name', ['template_name' => $templateName]);

        return $rows[0] ?? null;
    }
}
