<?php

declare(strict_types=1);

namespace App\Workflow;

/**
 * The only route by which a workflow step is allowed to touch the outside
 * world.
 *
 * WHY AN INTERFACE AND NOT DIRECT CALLS: AC-003 and the ToolGateway/AIGateway
 * split already established that the component which DECIDES must not be the
 * component which ACTS. App\Workflow\Orchestrator decides - is this a replay,
 * is it approved, must it be compensated - and hands the verb to whatever
 * implements this interface. That keeps every orchestration rule testable
 * without a mail server or a payment provider, and it means a reviewer can see
 * the complete list of effects a workflow can have by reading one
 * implementation.
 *
 * IMPLEMENTATIONS MUST NOT RE-CHECK IDEMPOTENCY OR APPROVAL. The orchestrator
 * has already claimed the Redis key and confirmed the approver before it calls
 * perform(): an effector that "helpfully" repeats those checks creates a second
 * place where they can drift out of agreement with the first.
 *
 * © AI WebScapes 2026
 */
interface WorkflowEffector
{
    /**
     * Performs the named step. Called at most once per idempotency key.
     */
    public function perform(string $stepType, string $workflowId): void;

    /**
     * Undoes an already-performed step (FR-ORCH-001).
     *
     * @param string $compensatingType The COMPENSATING verb ('refund'), not the
     *                                 verb being undone ('charge'): the caller
     *                                 owns the mapping, so an effector cannot
     *                                 silently disagree about what undoing a
     *                                 step means.
     */
    public function compensate(string $compensatingType, string $workflowId): void;
}
