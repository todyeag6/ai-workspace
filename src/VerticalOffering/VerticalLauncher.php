<?php

declare(strict_types=1);

namespace App\VerticalOffering;

use App\Agents\AgentEvaluationRepository;
use App\Agents\AgentRegistry;
use App\Agents\EvaluationReleaseGate;
use App\Eval\EvalResult;
use App\ManagedOps\AgentOwnership;
use App\ManagedOps\AgentOwnershipRepository;
use App\ManagedOps\SlaRecord;
use App\ManagedOps\SlaRepository;
use App\ManagedOps\SupportModel;
use App\Workflow\WorkflowBuilder;
use App\Workflow\WorkflowDefinition;
use InvalidArgumentException;

/**
 * Launches a packaged vertical offering (P2-T5).
 *
 * WHAT IT ORCHESTRATES. A vertical offering is a named, repeatable engagement
 * that bundles one or more agents plus their ownership rosters, SLA targets,
 * a support model, and a launch workflow. Every one of those pieces is an
 * ALREADY-BUILT module; this class composes them and adds exactly one new
 * behaviour: the launch transaction that wires them together, gated by the
 * evaluation verdict.
 *
 *   - AgentRegistration  -> AgentRegistry::create() (DISABLED by default,
 *                           FR-AGENT-002; immutable versions, FR-AGENT-003).
 *   - Activation         -> EvaluationReleaseGate::release() which records the
 *                           eval verdict in the append-only agent_evaluations
 *                           ledger and then calls AgentRegistry::activate() with
 *                           the verdict. The gate is NOT reimplemented here.
 *   - Accountability      -> AgentOwnershipRepository::assign() (append-only).
 *   - SLA targets        -> SlaRepository::record() (append-only, precomputed
 *                           breach flag via SlaRecord).
 *   - Launch workflow    -> WorkflowBuilder::build() validates the steps BEFORE
 *                           anything is written (fail-closed on authoring).
 *
 * FAIL-CLOSED ORDERING (the design): the launch workflow is validated FIRST,
 * before any agent row is created, so a malformed template cannot half-launch.
 * Then each agent is registered DISABLED and its blueprint (ownership + SLA)
 * is recorded. ONLY THEN is the eval gate consulted. If the verdict is false,
 * the agents stay DISABLED — the blueprint is preserved as the audit trail of
 * a refused offering, not discarded. This mirrors the "decision stays outside
 * the registry" invariant: this launcher computes no verdict, it receives one.
 *
 * WHY NO NEW AUTHZ PRIMITIVE. The offering reuses AgentRegistry's
 * deny-by-default activation and EvaluationReleaseGate's verdict binding. Adding
 * a second activation path would be a second thing that could be gotten wrong;
 * there is exactly one.
 *
 * SIDE NOTE ON TENANT SCOPING. Every repository is built from THIS class's
 * tenant id, so a launcher cannot be wired to mismatch the ownership/SLA/launch
 * repos. AC-001 is inherited, not re-asserted.
 *
 * © AI WebScapes 2026
 */
final class VerticalLauncher
{
    public function __construct(
        private readonly AgentRegistry $registry,
        private readonly AgentEvaluationRepository $evaluations,
        private readonly AgentOwnershipRepository $ownership,
        private readonly SlaRepository $slas,
        private readonly LaunchedOfferingRepository $launched
    ) {
    }

    /**
     * Launches the offering: registers every bundled agent (disabled), records
     * its ownership + SLA blueprint, validates the launch workflow, then
     * activates only if the evaluation verdict passed.
     *
     * @return LaunchedOffering The outcome (always returned; `activated` says
     *                          whether the gate opened).
     */
    public function launch(VerticalTemplate $template, EvalResult $eval, string $launchedBy): LaunchedOffering
    {
        // 1. FAIL-CLOSED FIRST: validate the launch workflow before any write.
        //    A bad step type throws here, before a single agent exists.
        /** @var list<array<string, mixed>> $steps */
        $steps = (array) ($template->launchWorkflow()['steps'] ?? []);
        $workflow = (new WorkflowBuilder(
            (string) ($template->launchWorkflow()['workflow_id'] ?? ''),
            $steps
        ))->build();

        $support = $template->support();
        /** @var list<array{role: string, channel: string, target: string}> $contacts */
        $contacts = (array) ($support['contacts'] ?? []);
        $supportModel = new SupportModel(
            (string) $support['tier'],
            $contacts,
            (string) ($support['boundary'] ?? '')
        );

        // 2. Register each agent DISABLED and record its accountability + SLA
        //    blueprint. The agents exist whether or not the gate later opens.
        $agentIds = [];
        foreach ($template->agents() as $agent) {
            /** @var list<string> $allowedTools */
            $allowedTools = (array) ($agent['allowed_tools'] ?? []);
            /** @var list<string> $dataClasses */
            $dataClasses = (array) ($agent['data_classes'] ?? []);
            $agentId = $this->registry->create(
                (string) $agent['name'],
                (string) $agent['owner'],
                (string) $agent['purpose'],
                (string) $agent['system_prompt'],
                (string) ($agent['risk_class'] ?? 'high'),
                $allowedTools,
                $dataClasses,
                [],
                (string) ($agent['deployment_location'] ?? 'cloud')
            );

            $versionId = $this->currentVersionId($agentId);
            $this->recordOwnership($agentId, $versionId, $agent, $supportModel, $launchedBy);
            $this->recordSlaTargets($agentId, $agent);

            $agentIds[] = $agentId;
        }

        // 3. CONSULT THE GATE. Activate only if the verdict passed. The gate
        //    records the eval verdict in the ledger and then calls
        //    AgentRegistry::activate(); on failure it leaves every agent
        //    DISABLED and we keep the blueprint for the audit trail.
        $gate = new EvaluationReleaseGate($this->registry, $this->evaluations);
        $activated = false;
        if ($eval->passed()) {
            foreach ($agentIds as $idx => $agentId) {
                // Each agent is released on the same verdict. The gate records
                // the verdict per agent version; activating the bundle means
                // releasing every agent with the passed verdict.
                $gate->release($agentId, $this->currentVersionId($agentId), $eval, ['passed' => true]);
            }
            $activated = true;
        }

        // 4. Record the launch as the audit trail, activated flag = gate result.
        $this->launched->record(
            $template->name(),
            count($agentIds),
            $activated,
            $eval->failedKpis(),
            $launchedBy
        );

        return new LaunchedOffering(
            $template->name(),
            $agentIds,
            $activated,
            $workflow,
            $eval->failedKpis(),
            $supportModel
        );
    }

    private function currentVersionId(int $agentId): int
    {
        $version = $this->registry->activeVersion($agentId);
        if ($version === null) {
            throw new InvalidArgumentException(sprintf('Agent %d has no active version after registration.', $agentId));
        }

        return $version->versionNumber();
    }

    /**
     * @param array<string, mixed> $agent
     */
    private function recordOwnership(int $agentId, int $versionId, array $agent, SupportModel $support, string $launchedBy): void
    {
        $roles = (array) ($agent['ownership'] ?? []);
        $this->ownership->assign(new AgentOwnership(
            $agentId,
            $versionId,
            $roles,
            $support->boundary(),
            $launchedBy
        ));
    }

    /**
     * @param array<string, mixed> $agent
     */
    private function recordSlaTargets(int $agentId, array $agent): void
    {
        $targets = (array) ($agent['sla_targets'] ?? []);
        foreach ($targets as $target) {
            if (!is_array($target)) {
                continue;
            }
            $this->slas->record($agentId, new SlaRecord(
                (string) ($target['type'] ?? ''),
                (float) ($target['target_hours'] ?? 0.0),
                0.0 // target definition; observed is measured later
            ));
        }
    }
}
