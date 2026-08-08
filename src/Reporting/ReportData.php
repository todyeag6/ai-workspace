<?php

declare(strict_types=1);

namespace App\Reporting;

/**
 * The data a report is assembled from (P2-T3 reporting suite).
 *
 * A plain, side-effect-free value object: the assembler renders it and the
 * controller/repository builds it from real sources (agents, the evaluation
 * ledger, workflow run history, dashboard metrics). Keeping the shape apart
 * from I/O means every report type is unit-testable without MySQL, mirroring
 * the dashboard read-model (FR-DASH) and the workflow definition.
 *
 * The six report kinds map to the BRD: Table 2 product capabilities
 * (operational control, KPI visualization, audit history, exceptions, cost,
 * security posture; managed-services reporting + SLA), Table 4 KPI categories
 * (Operational, Security), BR-12.4 release-gate acceptance, and the AI
 * Opportunity & Readiness Assessment engagement (BR-6.1, OBJ-08).
 *
 * @property-read string $kind assessment|operational|executive|security|sla|acceptance
 *
 * © AI WebScapes 2026
 */
final class ReportData
{
    /**
     * @param string $kind One of the six report kinds above.
     * @param string $title Human-readable title.
     * @param array<string, mixed> $metrics Key => value (scalar) metric pairs.
     * @param list<array<string, mixed>> $sections Structured rows for the body.
     * @param string $generatedAt ISO-8601 timestamp of assembly.
     */
    public function __construct(
        public readonly string $kind,
        public readonly string $title,
        public readonly array $metrics,
        public readonly array $sections,
        public readonly string $generatedAt
    ) {
    }
}
