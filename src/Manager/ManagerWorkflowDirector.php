<?php

declare(strict_types=1);

namespace App\Manager;

use App\Workflow\WorkflowDefinition;
use InvalidArgumentException;

final class ManagerWorkflowDirector
{
    /**
     * @param list<array{type: string, risk: string, description: string, dependencies: list<int>}> $tasks
     */
    public function build(string $workflowId, array $tasks): WorkflowDefinition
    {
        if ($workflowId === '') {
            throw new InvalidArgumentException('A workflow requires a non-empty id.');
        }
        if ($tasks === []) {
            throw new InvalidArgumentException('A workflow requires at least one task.');
        }

        $steps = [];
        foreach ($tasks as $task) {
            $risk = $task['risk'];
            if (!in_array($risk, ['low', 'medium', 'high', 'critical'], true)) {
                $risk = 'low';
            }
            $steps[] = ['type' => $task['type'], 'risk' => $risk];
        }

        return new WorkflowDefinition($workflowId, $steps, false);
    }
}
