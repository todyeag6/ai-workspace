<?php

declare(strict_types=1);

namespace App\Manager;

use App\AI\AIGateway;
use App\AI\AIRequest;

final class TaskDecomposer
{
    private const SYSTEM_PROMPT = 'You are a task decomposition assistant. Given a work description, '
        . 'break it into bite-sized tasks (2-5 minutes each). Return a JSON object with a "tasks" array '
        . 'where each element has: "type" (string, the task type), "risk" (one of: low, medium, high, critical), '
        . '"description" (string, what the task does), "required_tools" (array of tool names this task needs), '
        . '"dependencies" (array of task indices this depends on). '
        . 'Each task should be independently executable. Do not add any other keys.';

    public function __construct(
        private readonly AIGateway $gateway,
        private readonly string $model,
    ) {
    }

    /**
     * @return list<array{type: string, risk: string, description: string, required_tools: list<string>, dependencies: list<int>}>
     */
    public function decompose(string $workDescription, int $tenantId): array
    {
        $request = new AIRequest(
            model: $this->model,
            modelVersion: '1.0',
            configVersion: '1.0',
            purpose: 'task-decomposition',
            tenantId: $tenantId,
            dataClassification: 'internal',
            tokenLimit: 2000,
            costLimitCents: 5,
            costPerThousandTokensCents: 1,
            timeoutSeconds: 30,
            outputSchema: ['tasks' => 'array'],
            prompt: self::SYSTEM_PROMPT . "\n\nWork to decompose:\n" . $workDescription,
        );

        $result = $this->gateway->complete($request);

        if (!$result->valid || $result->payload === null) {
            return $this->fallbackDecomposition($workDescription);
        }

        return $this->normalizeTasks($result->payload['tasks'] ?? []);
    }

    /**
     * @return list<array{type: string, risk: string, description: string, required_tools: list<string>, dependencies: list<int>}>
     */
    private function fallbackDecomposition(string $workDescription): array
    {
        return [
            [
                'type' => 'generic',
                'risk' => 'low',
                'description' => $workDescription,
                'required_tools' => [],
                'dependencies' => [],
            ],
        ];
    }

    /**
     * @param list<mixed> $tasks
     * @return list<array{type: string, risk: string, description: string, required_tools: list<string>, dependencies: list<int>}>
     */
    private function normalizeTasks(array $tasks): array
    {
        $normalized = [];
        foreach ($tasks as $task) {
            if (!is_array($task) || !isset($task['type'], $task['description'])) {
                continue;
            }
            $deps = [];
            if (is_array($task['dependencies'] ?? null)) {
                foreach ($task['dependencies'] as $dep) {
                    if (is_int($dep)) {
                        $deps[] = $dep;
                    }
                }
            }
            $tools = [];
            if (is_array($task['required_tools'] ?? null)) {
                foreach ($task['required_tools'] as $tool) {
                    if (is_string($tool)) {
                        $tools[] = $tool;
                    }
                }
            }
            $normalized[] = [
                'type' => (string) $task['type'],
                'risk' => in_array($task['risk'] ?? '', ['low', 'medium', 'high', 'critical'], true)
                    ? $task['risk'] : 'low',
                'description' => (string) $task['description'],
                'required_tools' => $tools,
                'dependencies' => $deps,
            ];
        }
        return $normalized;
    }
}
