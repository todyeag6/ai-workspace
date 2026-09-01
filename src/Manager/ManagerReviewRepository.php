<?php

declare(strict_types=1);

namespace App\Manager;

use App\Data\TenantRepository;
use App\Agents\JsonColumn;
use PDO;

final class ManagerReviewRepository extends TenantRepository
{
    protected function table(): string
    {
        return 'manager_reviews';
    }

    protected function columns(): array
    {
        return ['id', 'manager_task_id', 'review_type', 'verdict', 'findings', 'reviewer_model', 'created_at'];
    }

    /**
     * @param list<string> $findings
     */
    public function add(
        int $managerTaskId,
        string $reviewType,
        string $verdict,
        array $findings,
        ?string $reviewerModel
    ): int {
        return (int) $this->insertScoped([
            'manager_task_id' => $managerTaskId,
            'review_type' => $reviewType,
            'verdict' => $verdict,
            'findings' => JsonColumn::encodeList($findings),
            'reviewer_model' => $reviewerModel,
        ]);
    }

    /**
     * @return list<array<string, scalar|null>>
     */
    public function forTask(int $managerTaskId): array
    {
        $rows = $this->selectScoped('manager_task_id = :task_id', ['task_id' => $managerTaskId]);

        $reviews = [];
        foreach ($rows as $row) {
            $reviews[] = $row;
        }
        return $reviews;
    }
}
