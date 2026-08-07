<?php

declare(strict_types=1);

namespace App\Workflow;

use App\AI\ActionAuthority;
use App\AI\AutonomousActionRejected;
use PDO;

/**
 * Executes a workflow's steps under three rules (FR-ORCH-001/002/003).
 *
 *   1. FR-ORCH-002 - a retry repeats no effect. Every step that can touch the
 *      outside world claims a Redis key with SET NX BEFORE the effector is
 *      called. A second run with the same key is told the key is taken and
 *      skips the step, so replay is effect-free rather than merely unlikely.
 *
 *   2. FR-ORCH-003 - a 'high' or 'critical' step does not execute until a
 *      HUMAN approver id has been recorded for the workflow. This is FR-AI-006
 *      at orchestration level: App\AI\ActionAuthority refuses to let anything
 *      autonomous authorise a high-impact action, and the only thing that can
 *      lift the refusal is approve(), which takes a person's id. There is no
 *      system approver and no "the model said it was fine" path.
 *
 *   3. FR-ORCH-001 - when a step fails, the side-effecting steps that already
 *      succeeded are compensated in reverse order. Rollback is not available:
 *      an email is sent and a card is charged outside this transaction, so the
 *      only honest undo is another action.
 *
 * IT DECIDES, IT DOES NOT ACT. Every effect goes through the injected
 * WorkflowEffector (AC-003, mirroring ToolGateway). This class holds no HTTP
 * client, no mailer and no payment SDK, which is what makes the rules above
 * testable and what stops "just call the API here" from ever being the shortest
 * path through the code.
 *
 * WHY THE APPROVAL GATE RUNS BEFORE THE CLAIM: claiming first would burn the
 * idempotency key on a step that was then blocked, and the post-approval run
 * would find the key taken and skip the action it was finally allowed to take.
 * Blocked steps therefore claim nothing, and approve() resumes them using the
 * key recorded on the step row.
 *
 * STATED LIMIT: retries with backoff, cancellation and dead-lettering are named
 * in the plan and are NOT implemented here. Their absence is visible (a caller
 * re-invokes run() itself) rather than faked by a half-working scheduler.
 *
 * © AI WebScapes 2026
 */
final class Orchestrator
{
    /**
     * FR-ORCH-001. Mirrors the workflow_compensations rows seeded by
     * migrations/004_workflows.sql - kept in code as well so compensation does
     * not need a healthy database round trip at the exact moment the workflow
     * is already failing. A step type absent from this map has no undo and is
     * left alone rather than being compensated by a guess.
     *
     * @var array<string, string>
     */
    private const COMPENSATIONS = [
        'charge' => 'refund',
        'reserve_stock' => 'release_stock',
    ];

    /**
     * The step type that means "this workflow failed here". Kept as a constant
     * so the compensation path has one named trigger instead of a literal
     * spread over the file.
     */
    private const FAILURE_STEP = 'fail';

    public function __construct(
        private PDO $pdo,
        private RedisIdempotency $idempotency,
        private WorkflowEffector $effector,
        private ActionAuthority $authority
    ) {
    }

    /**
     * Runs $steps for $workflowId and reports what each one did.
     *
     * @param list<array{type: string, risk?: string}> $steps
     * @param string|null $idempotencyKey Caller-supplied replay key. When null,
     *                                    a key is DERIVED from the workflow id
     *                                    and the step shape, so an unkeyed
     *                                    retry of an identical run is still
     *                                    recognised as a replay.
     *
     * @return array{
     *     run_id: int,
     *     status: string,
     *     steps: list<array{type: string, status: string}>
     * }
     */
    public function run(string $workflowId, array $steps, ?string $idempotencyKey = null): mixed
    {
        $approverId = $this->approverFor($workflowId);
        $baseKey = $idempotencyKey ?? $this->deriveKey($workflowId, $steps);
        $runId = $this->recordRun($workflowId, $baseKey, $approverId);

        /** @var list<string> $performed */
        $performed = [];
        /** @var list<array{type: string, status: string}> $outcome */
        $outcome = [];
        $runStatus = 'completed';

        foreach ($steps as $index => $step) {
            $type = $step['type'];
            $risk = strtolower(trim($step['risk'] ?? 'low'));
            $stepKey = $this->stepKey($workflowId, $baseKey, $index, $type);

            if ($type === self::FAILURE_STEP) {
                $this->recordStep($runId, $index, $type, $risk, 'failed', null);
                $this->compensate($workflowId, $performed);
                $outcome[] = ['type' => $type, 'status' => 'failed'];
                $runStatus = 'compensated';
                break;
            }

            if (!$this->mayExecute($type, $risk, $approverId)) {
                // FR-ORCH-003: recorded, not executed, and resumable by
                // approve(). No Redis claim - see the class comment.
                $this->recordStep($runId, $index, $type, $risk, 'blocked', $stepKey);
                $outcome[] = ['type' => $type, 'status' => 'blocked'];
                $runStatus = 'awaiting_approval';
                continue;
            }

            if (!$this->idempotency->claim($stepKey)) {
                // FR-ORCH-002: someone already holds this key, so the effect
                // has happened. Doing nothing here IS the correct behaviour.
                $this->recordStep($runId, $index, $type, $risk, 'skipped', $stepKey);
                $outcome[] = ['type' => $type, 'status' => 'skipped'];
                continue;
            }

            $this->effector->perform($type, $workflowId);
            $performed[] = $type;
            $this->recordStep($runId, $index, $type, $risk, 'executed', $stepKey);
            $outcome[] = ['type' => $type, 'status' => 'executed'];
        }

        $this->updateRunStatus($runId, $runStatus);

        return ['run_id' => $runId, 'status' => $runStatus, 'steps' => $outcome];
    }

    /**
     * Records a HUMAN sign-off for $workflowId and resumes the steps that were
     * blocked waiting for it (FR-ORCH-003).
     *
     * Resuming here rather than making the caller re-run means approval is what
     * releases the action, not a second call that might never come - while the
     * Redis claim still guarantees that a re-run afterwards repeats nothing.
     */
    public function approve(string $workflowId, int $approverId): void
    {
        $statement = $this->pdo->prepare(
            'INSERT INTO workflow_approvals (workflow_id, approver_id) VALUES (?, ?) AS incoming '
            . 'ON DUPLICATE KEY UPDATE approver_id = incoming.approver_id'
        );
        $statement->execute([$workflowId, $approverId]);

        $stamp = $this->pdo->prepare('UPDATE workflow_runs SET approver_id = ? WHERE workflow_id = ?');
        $stamp->execute([$approverId, $workflowId]);

        $this->resumeBlockedSteps($workflowId);
    }

    /**
     * FR-ORCH-003 / FR-AI-006. A recorded human approver is the ONLY thing that
     * permits a high-impact step. Without one, ActionAuthority decides, and it
     * refuses 'high', 'critical' and anything it does not recognise.
     */
    private function mayExecute(string $stepType, string $risk, ?int $approverId): bool
    {
        if ($approverId !== null) {
            return true;
        }

        try {
            $this->authority->authorizeTransaction($stepType, $risk);
        } catch (AutonomousActionRejected) {
            return false;
        }

        return true;
    }

    /**
     * @param list<string> $performed Step types already executed, in order.
     */
    private function compensate(string $workflowId, array $performed): void
    {
        // Reverse order: the last effect is the least entangled with the ones
        // before it, so undoing backwards is the only ordering that cannot
        // strand a dependent step.
        foreach (array_reverse($performed) as $type) {
            $compensating = self::COMPENSATIONS[$type] ?? null;
            if ($compensating === null) {
                continue;
            }

            $this->effector->compensate($compensating, $workflowId);
        }
    }

    private function resumeBlockedSteps(string $workflowId): void
    {
        $statement = $this->pdo->prepare(
            'SELECT s.id, s.step_type, s.idempotency_key FROM workflow_steps s '
            . 'INNER JOIN workflow_runs r ON r.id = s.workflow_run_id '
            . 'WHERE r.workflow_id = ? AND s.status = ? ORDER BY s.id'
        );
        $statement->execute([$workflowId, 'blocked']);

        /** @var list<array{id: int|string, step_type: string, idempotency_key: string|null}> $rows */
        $rows = $statement->fetchAll(PDO::FETCH_ASSOC);

        foreach ($rows as $row) {
            $key = $row['idempotency_key'] ?? $this->stepKey($workflowId, 'resume', 0, $row['step_type']);

            if (!$this->idempotency->claim($key)) {
                $this->markStep((int) $row['id'], 'skipped');
                continue;
            }

            $this->effector->perform($row['step_type'], $workflowId);
            $this->markStep((int) $row['id'], 'executed');
        }
    }

    private function approverFor(string $workflowId): ?int
    {
        $statement = $this->pdo->prepare(
            'SELECT approver_id FROM workflow_approvals WHERE workflow_id = ? LIMIT 1'
        );
        $statement->execute([$workflowId]);
        $value = $statement->fetchColumn();

        return is_numeric($value) ? (int) $value : null;
    }

    private function recordRun(string $workflowId, string $idempotencyKey, ?int $approverId): int
    {
        $statement = $this->pdo->prepare(
            'INSERT INTO workflow_runs (workflow_id, idempotency_key, status, approver_id) '
            . 'VALUES (?, ?, ?, ?)'
        );
        $statement->execute([$workflowId, $idempotencyKey, 'running', $approverId]);

        return (int) $this->pdo->lastInsertId();
    }

    private function recordStep(
        int $runId,
        int $index,
        string $type,
        string $risk,
        string $status,
        ?string $idempotencyKey
    ): void {
        $statement = $this->pdo->prepare(
            'INSERT INTO workflow_steps '
            . '(workflow_run_id, step_index, step_type, risk, status, idempotency_key) '
            . 'VALUES (?, ?, ?, ?, ?, ?)'
        );
        // An unrecognised risk class is stored as 'critical', not silently
        // downgraded: the step was refused as unknown, and the row has to say
        // something the ENUM accepts without understating what was attempted.
        $statement->execute([
            $runId,
            $index,
            $type,
            in_array($risk, ['low', 'medium', 'high', 'critical'], true) ? $risk : 'critical',
            $status,
            $idempotencyKey,
        ]);
    }

    private function markStep(int $stepId, string $status): void
    {
        $statement = $this->pdo->prepare('UPDATE workflow_steps SET status = ? WHERE id = ?');
        $statement->execute([$status, $stepId]);
    }

    private function updateRunStatus(int $runId, string $status): void
    {
        $statement = $this->pdo->prepare('UPDATE workflow_runs SET status = ? WHERE id = ?');
        $statement->execute([$status, $runId]);
    }

    /**
     * Derives a replay key for a caller that supplied none.
     *
     * Hashes the workflow id together with the ORDERED step shape: two runs of
     * the same steps are the same intent and must not double-fire, while
     * changing or reordering a step is a different intent and gets its own key.
     *
     * @param list<array{type: string, risk?: string}> $steps
     */
    private function deriveKey(string $workflowId, array $steps): string
    {
        $shape = '';
        foreach ($steps as $index => $step) {
            $shape .= $index . ':' . $step['type'] . ':' . ($step['risk'] ?? 'low') . '|';
        }

        return 'derived:' . hash('sha256', $workflowId . '|' . $shape);
    }

    /**
     * One key per step, not per run: a workflow that sends an email and then
     * charges a card must be able to replay past the email without also
     * replaying the charge.
     */
    private function stepKey(string $workflowId, string $baseKey, int $index, string $type): string
    {
        return hash('sha256', $workflowId . '|' . $baseKey . '|' . $index . '|' . $type);
    }
}
