<?php

declare(strict_types=1);

namespace App\Tests\Workflow;

use App\Workflow\WorkflowEffector;

/**
 * Test double for the only collaborator the orchestrator is allowed to have
 * side effects through.
 *
 * WHY A HAND-WRITTEN FAKE AND NOT A MOCK: the assertions here are about HOW
 * MANY times an effect happened across two separate run() calls (FR-ORCH-002),
 * and a counter that survives the call is clearer to read - and harder to get
 * accidentally right - than an expects($this->once()) written after the fact.
 *
 * Nothing in this class talks to a network, a mail server or a payment
 * provider: that is the AC-003 split the orchestrator is built around, and the
 * test suite must not be the place it is quietly broken.
 *
 * © AI WebScapes 2026
 */
final class RecordingEffector implements WorkflowEffector
{
    public int $sendCount = 0;

    public bool $refundCalled = false;

    public bool $refundIssued = false;

    public int $chargeCount = 0;

    public function perform(string $stepType, string $workflowId): void
    {
        if ($stepType === 'send_email') {
            $this->sendCount++;
            return;
        }

        if ($stepType === 'refund') {
            $this->refundCalled = true;
            return;
        }

        if ($stepType === 'charge') {
            $this->chargeCount++;
        }
    }

    public function compensate(string $compensatingType, string $workflowId): void
    {
        if ($compensatingType === 'refund') {
            $this->refundIssued = true;
        }
    }
}
