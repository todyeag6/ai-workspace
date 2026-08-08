<?php

declare(strict_types=1);

namespace App\Workflow;

/**
 * An immutable, validated workflow definition (P2-T3 "workflow builder").
 *
 * The P1-T9 Orchestrator executes `list<array{type, risk?}>` steps but performs
 * NO validation of them - it is a runtime engine, and validating caller-supplied
 * structure at execution time would put a parse error in the middle of a
 * money-moving run. This class is the missing definition seam: it is built ONLY
 * through App\Workflow\WorkflowBuilder, which refuses malformed definitions
 * before anything runs. The Orchestrator therefore receives a definition it can
 * trust, and a bad workflow is caught at authoring time, not at charge time.
 *
 * It is a plain value object with no PDO/Redis/mailer dependency, so it is
 * unit-testable without MySQL or Redis - mirroring the dashboard read-model
 * pattern (FR-DASH), where data shape lives apart from I/O.
 *
 * © AI WebScapes 2026
 */
final class WorkflowDefinition
{
    /**
     * @param list<array{type: string, risk: string}> $steps
     * @param bool $requiresApproval True when any step is high|critical impact.
     */
    public function __construct(
        public readonly string $workflowId,
        public readonly array $steps,
        public readonly bool $requiresApproval
    ) {
    }

    /**
     * The shape the Orchestrator consumes. The builder guarantees every step
     * has a normalised risk, so the engine's `$step['risk'] ?? 'low'` fallback
     * is never triggered by a definition this class produced.
     *
     * @return list<array{type: string, risk: string}>
     */
    public function steps(): array
    {
        return $this->steps;
    }
}
