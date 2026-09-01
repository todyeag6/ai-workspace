<?php

declare(strict_types=1);

namespace App\Manager;

use App\Data\TenantRepository;
use App\Agents\JsonColumn;
use PDO;

final class ManagerTaskRepository extends TenantRepository
{
    protected function table(): string
    {
        return 'manager_tasks';
    }

    protected function columns(): array
    {
        return [
            'id', 'tenant_id', 'workflow_id', 'agent_id', 'task_type', 'risk',
            'status', 'spec_compliance', 'code_quality', 'revision_count',
            'context', 'result', 'created_at', 'updated_at',
        ];
    }

    /**
     * @param array<string, mixed> $context
     */
    public function add(
        ?string $workflowId,
        ?int $agentId,
        string $taskType,
        string $risk,
        array $context
    ): int {
        return (int) $this->insertScoped([
            'workflow_id' => $workflowId,
            'agent_id' => $agentId,
            'task_type' => $taskType,
            'risk' => $risk,
            'context' => JsonColumn::encodeMap($context),
        ]);
    }

    public function findTask(int $taskId): ?ManagerTask
    {
        $rows = $this->selectScoped('id = :id', ['id' => $taskId]);
        $row = $rows[0] ?? null;

        return $row === null ? null : $this->hydrate($row);
    }

    /**
     * @return list<ManagerTask>
     */
    public function findPendingReview(): array
    {
        $rows = $this->selectScoped(
            'status = :status AND (spec_compliance = :spec OR code_quality = :quality)',
            [
                'status' => ManagerTask::STATUS_COMPLETED,
                'spec' => ManagerTask::SPEC_PENDING,
                'quality' => ManagerTask::QUALITY_PENDING,
            ]
        );

        $tasks = [];
        foreach ($rows as $row) {
            $tasks[] = $this->hydrate($row);
        }
        return $tasks;
    }

    public function updateStatus(int $taskId, string $status): void
    {
        $this->updateScoped(['status' => $status], 'id = :id', ['id' => $taskId]);
    }

    public function updateSpecCompliance(int $taskId, string $verdict): void
    {
        $this->updateScoped(['spec_compliance' => $verdict], 'id = :id', ['id' => $taskId]);
    }

    public function updateCodeQuality(int $taskId, string $verdict): void
    {
        $this->updateScoped(['code_quality' => $verdict], 'id = :id', ['id' => $taskId]);
    }

    public function incrementRevision(int $taskId): void
    {
        $rows = $this->selectScoped('id = :id', ['id' => $taskId]);
        $current = (int) ($rows[0]['revision_count'] ?? 0);
        $this->updateScoped(['revision_count' => $current + 1], 'id = :id', ['id' => $taskId]);
    }

    /**
     * @param array<string, mixed> $result
     */
    public function updateResult(int $taskId, array $result): void
    {
        $this->updateScoped(['result' => JsonColumn::encodeMap($result)], 'id = :id', ['id' => $taskId]);
    }

    public function setWorkflowId(int $taskId, string $workflowId): void
    {
        $this->updateScoped(
            ['workflow_id' => $workflowId, 'status' => ManagerTask::STATUS_DISPATCHED],
            'id = :id',
            ['id' => $taskId]
        );
    }

    /**
     * @param array<string, scalar|null> $row
     */
    private function hydrate(array $row): ManagerTask
    {
        return new ManagerTask(
            (int) $row['id'],
            (int) $row['tenant_id'],
            $row['workflow_id'] !== null ? (string) $row['workflow_id'] : null,
            $row['agent_id'] !== null ? (int) $row['agent_id'] : null,
            (string) $row['task_type'],
            (string) $row['risk'],
            (string) $row['status'],
            (string) $row['spec_compliance'],
            (string) $row['code_quality'],
            (int) $row['revision_count'],
            JsonColumn::decodeMap((string) ($row['context'] ?? '{}')),
            $row['result'] !== null ? JsonColumn::decodeMap((string) $row['result']) : null,
        );
    }
}
