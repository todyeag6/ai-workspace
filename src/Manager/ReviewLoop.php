<?php

declare(strict_types=1);

namespace App\Manager;

use App\AI\AIGateway;
use App\AI\AIRequest;

final class ReviewLoop
{
    private const SPEC_SYSTEM_PROMPT = 'You are a spec compliance reviewer. Given a task spec and its '
        . 'implementation result, verify that the implementation matches the spec. Return JSON with '
        . 'exactly these keys: "verdict" (one of: pass, fail), "gaps" (array of strings describing '
        . 'what is missing or incorrect). Do not add other keys.';

    private const QUALITY_SYSTEM_PROMPT = 'You are a code quality reviewer. Given a task spec and its '
        . 'implementation result, verify code quality, conventions, error handling, and security. '
        . 'Return JSON with exactly these keys: "verdict" (one of: approved, changes_requested), '
        . '"issues" (array of strings describing issues found). Do not add other keys.';

    public function __construct(
        private readonly AIGateway $gateway,
        private readonly string $model,
    ) {
    }

    /**
     * @param array<string, mixed> $taskContext
     * @param array<string, mixed> $taskResult
     * @return array{verdict: string, findings: list<string>}
     */
    public function reviewSpecCompliance(array $taskContext, array $taskResult, int $tenantId): array
    {
        $prompt = self::SPEC_SYSTEM_PROMPT . "\n\n"
            . "Task Spec:\n" . json_encode($taskContext, JSON_PRETTY_PRINT) . "\n\n"
            . "Implementation Result:\n" . json_encode($taskResult, JSON_PRETTY_PRINT);

        $request = $this->buildRequest('spec-compliance-review', $tenantId, $prompt);
        $result = $this->gateway->complete($request);

        if (!$result->valid || $result->payload === null) {
            return ['verdict' => 'fail', 'findings' => ['Review failed — model output invalid.']];
        }

        return [
            'verdict' => ($result->payload['verdict'] ?? '') === 'pass' ? 'pass' : 'fail',
            'findings' => $this->extractStringList($result->payload['gaps'] ?? []),
        ];
    }

    /**
     * @param array<string, mixed> $taskContext
     * @param array<string, mixed> $taskResult
     * @return array{verdict: string, findings: list<string>}
     */
    public function reviewCodeQuality(array $taskContext, array $taskResult, int $tenantId): array
    {
        $prompt = self::QUALITY_SYSTEM_PROMPT . "\n\n"
            . "Task Spec:\n" . json_encode($taskContext, JSON_PRETTY_PRINT) . "\n\n"
            . "Implementation Result:\n" . json_encode($taskResult, JSON_PRETTY_PRINT);

        $request = $this->buildRequest('code-quality-review', $tenantId, $prompt);
        $result = $this->gateway->complete($request);

        if (!$result->valid || $result->payload === null) {
            return ['verdict' => 'changes_requested', 'findings' => ['Review failed — model output invalid.']];
        }

        return [
            'verdict' => ($result->payload['verdict'] ?? '') === 'approved' ? 'approved' : 'changes_requested',
            'findings' => $this->extractStringList($result->payload['issues'] ?? []),
        ];
    }

    private function buildRequest(string $purpose, int $tenantId, string $prompt): AIRequest
    {
        return new AIRequest(
            model: $this->model,
            modelVersion: '1.0',
            configVersion: '1.0',
            purpose: $purpose,
            tenantId: $tenantId,
            dataClassification: 'internal',
            tokenLimit: 1500,
            costLimitCents: 3,
            costPerThousandTokensCents: 1,
            timeoutSeconds: 30,
            outputSchema: ['verdict' => 'string', 'findings' => 'array'],
            prompt: $prompt,
        );
    }

    /**
     * @param mixed $value
     * @return list<string>
     */
    private function extractStringList(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }
        $list = [];
        foreach ($value as $item) {
            if (is_string($item)) {
                $list[] = $item;
            }
        }
        return $list;
    }
}
