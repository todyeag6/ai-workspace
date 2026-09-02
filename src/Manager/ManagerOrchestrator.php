<?php

declare(strict_types=1);

namespace App\Manager;

use App\AI\AIGateway;
use App\AI\AIRequest;
use App\Agents\AgentRegistry;
use App\Agents\JsonColumn;

final class ManagerOrchestrator
{
    private const DEFAULT_AGENT_PROMPT = 'You are a task execution agent. Complete the task described below to the best of your ability. Return a JSON object describing what you did and the outcome.';

    private TaskDecomposer $decomposer;
    private ReviewLoop $reviewLoop;
    private AgentSelector $agentSelector;

    public function __construct(
        private readonly AgentRegistry $agentRegistry,
        private readonly AIGateway $gateway,
        private readonly string $model,
        private readonly ManagerTaskRepository $taskRepo,
        private readonly ManagerReviewRepository $reviewRepo,
    ) {
        $this->decomposer = new TaskDecomposer($gateway, $model);
        $this->reviewLoop = new ReviewLoop($gateway, $model);
        $this->agentSelector = new AgentSelector($agentRegistry);
    }

    /**
     * Main entry point: decompose work into tasks, dispatch each to a
     * specialized sub-agent, run two-stage reviews, manage the revision loop.
     *
     * @return array<string, mixed>
     */
    public function manage(string $workDescription): array
    {
        $tasks = $this->decomposer->decompose($workDescription, $this->agentRegistry->tenantId());

        $results = [];
        foreach ($tasks as $taskDef) {
            $agent = $this->agentSelector->select($taskDef['type'], $taskDef['required_tools']);
            $agentId = $agent['id'] ?? null;

            if ($agentId === null) {
                $agentId = $this->createDefaultAgent($taskDef);
            }

            $taskId = $this->taskRepo->add(
                null,
                $agentId,
                $taskDef['type'],
                $taskDef['risk'],
                $taskDef,
            );

            $this->executeTaskWithRevisions($taskId);

            $task = $this->taskRepo->findTask($taskId);
            $results[] = [
                'id' => $taskId,
                'status' => $task?->status() ?? 'unknown',
            ];
        }

        $allPassed = $this->allTasksPassed($results);

        return [
            'status' => $allPassed ? 'completed' : 'partial',
            'tasks' => $results,
        ];
    }

    /**
     * Runs the dispatch → review → revise loop for a single task.
     * Bounded by ManagerTask::canRevise() (max 3 iterations).
     */
    private function executeTaskWithRevisions(int $taskId): void
    {
        $feedback = '';

        while (true) {
            $task = $this->taskRepo->findTask($taskId);
            if ($task === null || $task->status() === ManagerTask::STATUS_COMPLETED) {
                return;
            }

            if (!$task->canRevise()) {
                $this->taskRepo->updateStatus($taskId, ManagerTask::STATUS_ESCALATED);
                return;
            }

            $this->dispatchToSubagent($task, $feedback);

            $task = $this->taskRepo->findTask($taskId);
            if ($task === null || $task->status() !== ManagerTask::STATUS_COMPLETED) {
                return;
            }

            $verdict = $this->runReviews($taskId);

            if ($verdict === 'pass') {
                return;
            }

            $feedback = $this->formatReviewFeedback($taskId);
            $this->taskRepo->incrementRevision($taskId);
        }
    }

    /**
     * Dispatches a task to its assigned sub-agent via AIGateway.
     */
    private function dispatchToSubagent(ManagerTask $task, string $feedback = ''): void
    {
        $agentId = $task->agentId();
        if ($agentId === null) {
            $this->taskRepo->updateStatus($task->id(), ManagerTask::STATUS_FAILED);
            return;
        }

        $version = $this->agentRegistry->activeVersion($agentId);
        if ($version === null) {
            $this->taskRepo->updateStatus($task->id(), ManagerTask::STATUS_FAILED);
            return;
        }

        $modelConfig = $version->modelConfig();
        $model = (string) ($modelConfig['model'] ?? $this->model);
        $tokenLimit = (int) ($modelConfig['token_limit'] ?? 2000);
        $costLimitCents = (int) ($modelConfig['cost_limit_cents'] ?? 5);
        $timeoutSeconds = (int) ($modelConfig['timeout_seconds'] ?? 30);
        $costPerThousandTokensCents = (int) ($modelConfig['cost_per_thousand_tokens_cents'] ?? 0);

        $prompt = $version->systemPrompt();
        if ($feedback !== '') {
            $prompt .= "\n\n--- REVIEW FEEDBACK ---\n" . $feedback . "\n\nAddress the above feedback and re-submit.";
        }
        $prompt .= "\n\n--- TASK ---\n" . ($task->context()['description'] ?? '');

        $schema = ['result' => 'string'];
        $rawSchema = $modelConfig['output_schema'] ?? null;
        if ($rawSchema !== null) {
            /** @var array<string, mixed> $rawSchema */
            $schema = (array) $rawSchema;
        }

        $request = new AIRequest(
            model: $model,
            modelVersion: '1.0',
            configVersion: '1.0',
            purpose: $task->taskType(),
            tenantId: $task->tenantId(),
            dataClassification: 'internal',
            tokenLimit: $tokenLimit,
            costLimitCents: $costLimitCents,
            costPerThousandTokensCents: $costPerThousandTokensCents,
            timeoutSeconds: $timeoutSeconds,
            outputSchema: $schema,
            prompt: $prompt,
        );

        try {
            $result = $this->gateway->complete($request);
        } catch (\Throwable $e) {
            $this->taskRepo->updateResult($task->id(), ['error' => 'dispatch_failed']);
            $this->taskRepo->updateStatus($task->id(), ManagerTask::STATUS_FAILED);
            return;
        }

        if (!$result->valid) {
            $this->taskRepo->updateResult($task->id(), ['errors' => $result->errors]);
            $this->taskRepo->updateStatus($task->id(), ManagerTask::STATUS_FAILED);
            return;
        }

        $this->taskRepo->updateResult($task->id(), $result->payload ?? []);
        $this->taskRepo->updateStatus($task->id(), ManagerTask::STATUS_COMPLETED);
    }

    /**
     * Creates a default agent for a task type when no existing agent matches.
     *
     * @param array{type: string, risk: string, description: string, required_tools: list<string>, dependencies: list<int>} $taskDef
     */
    private function createDefaultAgent(array $taskDef): int
    {
        $type = $taskDef['type'];
        $agentId = $this->agentRegistry->create(
            name: 'manager-default-' . $type,
            owner: 'manager-agent',
            purpose: $type,
            systemPrompt: self::DEFAULT_AGENT_PROMPT,
            riskClass: $taskDef['risk'],
            allowedTools: [],
            modelConfig: ['model' => $this->model],
        );

        $this->agentRegistry->activate($agentId, true);

        return $agentId;
    }

    /**
     * Runs two-stage review (spec compliance → code quality).
     *
     * @return 'pass'|'spec_fail'|'quality_fail'
     */
    private function runReviews(int $taskId): string
    {
        $task = $this->taskRepo->findTask($taskId);
        if ($task === null) {
            return 'spec_fail';
        }

        // Stage 1: Spec compliance
        $specResult = $this->reviewLoop->reviewSpecCompliance(
            $task->context(),
            $task->result() ?? [],
            $task->tenantId(),
        );

        $this->reviewRepo->add(
            $taskId,
            'spec_compliance',
            $specResult['verdict'],
            $specResult['findings'],
            $this->model,
        );

        $specVerdict = $specResult['verdict'] === 'pass'
            ? ManagerTask::SPEC_PASS
            : ManagerTask::SPEC_FAIL;
        $this->taskRepo->updateSpecCompliance($taskId, $specVerdict);

        if ($specVerdict !== ManagerTask::SPEC_PASS) {
            return 'spec_fail';
        }

        // Stage 2: Code quality
        $qualityResult = $this->reviewLoop->reviewCodeQuality(
            $task->context(),
            $task->result() ?? [],
            $task->tenantId(),
        );

        $this->reviewRepo->add(
            $taskId,
            'code_quality',
            $qualityResult['verdict'],
            $qualityResult['findings'],
            $this->model,
        );

        $qualityVerdict = $qualityResult['verdict'] === 'approved'
            ? ManagerTask::QUALITY_APPROVED
            : ManagerTask::QUALITY_CHANGES_REQUESTED;
        $this->taskRepo->updateCodeQuality($taskId, $qualityVerdict);

        if ($qualityVerdict !== ManagerTask::QUALITY_APPROVED) {
            return 'quality_fail';
        }

        return 'pass';
    }

    /**
     * Collects review findings from the most recent review passes for feedback.
     */
    private function formatReviewFeedback(int $taskId): string
    {
        $reviews = $this->reviewRepo->forTask($taskId);
        $lines = [];

        foreach ($reviews as $review) {
            $type = $review['review_type'] ?? 'unknown';
            $verdict = $review['verdict'] ?? 'unknown';
            $findings = JsonColumn::decodeList((string) ($review['findings'] ?? '[]'));

            $lines[] = sprintf('[%s] %s:', $type, $verdict);
            foreach ($findings as $finding) {
                $lines[] = '  - ' . $finding;
            }
        }

        return implode("\n", $lines);
    }

    /**
     * @param list<array{id: int, status: string}> $results
     */
    private function allTasksPassed(array $results): bool
    {
        foreach ($results as $result) {
            if ($result['status'] !== 'completed') {
                return false;
            }
        }

        return true;
    }
}
