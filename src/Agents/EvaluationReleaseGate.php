<?php

declare(strict_types=1);

namespace App\Agents;

use App\Eval\EvalResult;

/**
 * The P2-T1 release gate that binds the evaluation verdict to activation
 * (FR-AGENT-003: "require evaluation before production activation").
 *
 * WHY A SEPARATE CLASS, NOT A FLAG ON activate(): AgentRegistry::activate() is
 * deliberately designed to never DECIDE whether a gate passed - it takes the
 * verdict as an argument and refuses when it is false, because a registry that
 * evaluated its own gates could be satisfied by fixing the registry. This
 * class is the thing that computes-and-records the verdict, then delegates the
 * actual refusal to activate(). The decision stays outside the registry; the
 * record of the decision stays in the append-only agent_evaluations ledger.
 *
 * SEQUENCE MATTERS: the evaluation row is written FIRST (durable evidence),
 * then activate() is called. If activate() refuses because the verdict was
 * false, the evidence already exists; if it refuses for another reason
 * (retired), the evidence still exists. The ledger is the source of truth for
 * "was this version evaluated, and did it pass", independent of the agent's
 * current status.
 *
 * © AI WebScapes 2026
 */
final class EvaluationReleaseGate
{
    public function __construct(
        private readonly AgentRegistry $registry,
        private readonly AgentEvaluationRepository $evaluations
    ) {
    }

    /**
     * Records the evaluation outcome and activates only if it passed.
     *
     * @param array<string, mixed> $thresholds The threshold rules in force,
     *                                          snapshotted onto the ledger row.
     * @throws \App\Agents\ReleaseGateNotMet When the evaluation did not pass.
     */
    public function release(int $agentId, int $versionId, EvalResult $result, array $thresholds): void
    {
        $this->evaluations->record(
            $agentId,
            $versionId,
            $result->passed(),
            $result->casesRun(),
            $result->failedKpis(),
            $thresholds
        );

        // activate() owns the refusal. It throws ReleaseGateNotMet when
        // evalPassed is false, or when the agent is retired, etc.
        $this->registry->activate($agentId, $result->passed());
    }
}
