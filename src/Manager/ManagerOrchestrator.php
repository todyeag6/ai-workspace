<?php

declare(strict_types=1);

namespace App\Manager;

use App\AI\AIGateway;
use App\Agents\AgentRegistry;

final class ManagerOrchestrator
{
    private TaskDecomposer $decomposer;
    private ReviewLoop $reviewLoop;

    public function __construct(
        private readonly AgentRegistry $agentRegistry,
        private readonly AIGateway $gateway,
        private readonly string $model,
        private readonly ManagerTaskRepository $taskRepo,
        private readonly ManagerReviewRepository $reviewRepo,
    ) {
        $this->decomposer = new TaskDecomposer($gateway, $model);
        $this->reviewLoop = new ReviewLoop($gateway, $model);
    }

    /**
     * Main entry point: decompose work into tasks, track them, run reviews.
     *
     * @return array<string, mixed>
     */
    public function manage(string $workDescription): array
    {
        $tasks = $this->decomposer->decompose($workDescription, $this->agentRegistry->tenantId());

        $results = [];
        foreach ($tasks as $taskDef) {
            $taskId = $this->taskRepo->add(
                null,
                null,
                $taskDef['type'],
                $taskDef['risk'],
                $taskDef,
            );

            $this->runReviews($taskId);

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

    private function runReviews(int $taskId): void
    {
        $task = $this->taskRepo->findTask($taskId);
        if ($task === null) {
            return;
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
            $this->handleRevision($taskId);
            return;
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
            $this->handleRevision($taskId);
        }
    }

    private function handleRevision(int $taskId): void
    {
        $task = $this->taskRepo->findTask($taskId);
        if ($task === null) {
            return;
        }

        if (!$task->canRevise()) {
            $this->taskRepo->updateStatus($taskId, ManagerTask::STATUS_ESCALATED);
            return;
        }

        $this->taskRepo->incrementRevision($taskId);
        $this->taskRepo->updateStatus($taskId, ManagerTask::STATUS_PENDING);
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
