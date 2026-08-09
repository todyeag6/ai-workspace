<?php

declare(strict_types=1);

namespace App\VerticalOffering;

use App\ManagedOps\SupportModel;
use App\Workflow\WorkflowDefinition;

/**
 * The outcome of a vertical-offering launch (P2-T5).
 *
 * Plain value object: no IO, no mutation. `activated` is the verdict of the
 * evaluation gate — true only when the gate opened and the bundled agents were
 * switched on; false when they remain DISABLED (the blueprint is still recorded
 * for the audit trail). The launcher returns this rather than throwing on a
 * refused gate, because a refused launch is a normal, recoverable outcome, not
 * an error.
 *
 * © AI WebScapes 2026
 */
final class LaunchedOffering
{
    /**
     * @param list<int> $agentIds
     * @param list<string> $failedKpis
     */
    public function __construct(
        public readonly string $templateName,
        public readonly array $agentIds,
        public readonly bool $activated,
        public readonly WorkflowDefinition $workflow,
        public readonly array $failedKpis,
        public readonly SupportModel $support
    ) {
    }
}
