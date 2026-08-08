<?php

declare(strict_types=1);

namespace App\Dashboard;

/**
 * The read-model the dashboard view renders (P1-T15: FR-DASH-001/002,
 * LFR-DASH-001/002/003).
 *
 * A plain value object, not a DB handle: the controller builds it from a
 * DashboardRepository (which owns all tenant-scoped I/O) and the view layer
 * reads it. Keeping it free of side effects means the dashboard's data shape is
 * unit-testable without MySQL.
 *
 * © AI WebScapes 2026
 */
final class DashboardView
{
    /**
     * @param array<string, int>          $leadStatusCounts  state => count (all LEAD_STATES present).
     * @param list<array<string, mixed>>  $awaitingHuman     pending AI analyses (LBR-5.8).
     * @param list<array<string, mixed>>  $failedDeliveries  failed outbound messages (LBR-5.8).
     */
    public function __construct(
        public readonly array $leadStatusCounts,
        public readonly array $awaitingHuman,
        public readonly array $failedDeliveries
    ) {
    }

    /**
     * LFR-DASH-001 - the pipeline state list, in canonical order.
     *
     * @return list<string>
     */
    public function states(): array
    {
        return array_keys($this->leadStatusCounts);
    }

    /**
     * FR-DASH-001 - per-state lead counts (all LEAD_STATES present).
     *
     * @return array<string, int>
     */
    public function leadStatusCounts(): array
    {
        return $this->leadStatusCounts;
    }

    /**
     * LBR-5.8 - the exceptions queue a human must work.
     *
     * @return list<array<string, mixed>>
     */
    public function awaitingHuman(): array
    {
        return $this->awaitingHuman;
    }

    /**
     * LBR-5.8 - the failed-delivery queue.
     *
     * @return list<array<string, mixed>>
     */
    public function failedDeliveries(): array
    {
        return $this->failedDeliveries;
    }
}
