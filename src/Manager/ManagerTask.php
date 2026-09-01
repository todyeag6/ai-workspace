<?php

declare(strict_types=1);

namespace App\Manager;

use InvalidArgumentException;

final class ManagerTask
{
    public const STATUS_PENDING = 'pending';
    public const STATUS_DISPATCHED = 'dispatched';
    public const STATUS_COMPLETED = 'completed';
    public const STATUS_FAILED = 'failed';
    public const STATUS_BLOCKED = 'blocked';
    public const STATUS_ESCALATED = 'escalated';

    public const SPEC_PENDING = 'pending';
    public const SPEC_PASS = 'pass';
    public const SPEC_FAIL = 'fail';

    public const QUALITY_PENDING = 'pending';
    public const QUALITY_APPROVED = 'approved';
    public const QUALITY_CHANGES_REQUESTED = 'changes_requested';

    /**
     * @param array<string, mixed> $context
     * @param array<string, mixed>|null $result
     */
    public function __construct(
        private readonly int $id,
        private readonly int $tenantId,
        private readonly ?string $workflowId,
        private readonly ?int $agentId,
        private readonly string $taskType,
        private readonly string $risk,
        private readonly string $status,
        private readonly string $specCompliance,
        private readonly string $codeQuality,
        private readonly int $revisionCount,
        private readonly array $context,
        private readonly ?array $result,
    ) {
        if (!in_array($risk, ['low', 'medium', 'high', 'critical'], true)) {
            throw new InvalidArgumentException(sprintf('Invalid risk class "%s".', $risk));
        }
    }

    public function id(): int
    {
        return $this->id;
    }

    public function tenantId(): int
    {
        return $this->tenantId;
    }

    public function workflowId(): ?string
    {
        return $this->workflowId;
    }

    public function agentId(): ?int
    {
        return $this->agentId;
    }

    public function taskType(): string
    {
        return $this->taskType;
    }

    public function risk(): string
    {
        return $this->risk;
    }

    public function status(): string
    {
        return $this->status;
    }

    public function specCompliance(): string
    {
        return $this->specCompliance;
    }

    public function codeQuality(): string
    {
        return $this->codeQuality;
    }

    public function revisionCount(): int
    {
        return $this->revisionCount;
    }

    /**
     * @return array<string, mixed>
     */
    public function context(): array
    {
        return $this->context;
    }

    /**
     * @return array<string, mixed>|null
     */
    public function result(): ?array
    {
        return $this->result;
    }

    public function requiresApproval(): bool
    {
        return in_array($this->risk, ['high', 'critical'], true);
    }

    public function isPendingReview(): bool
    {
        return $this->status === self::STATUS_COMPLETED
            && ($this->specCompliance === self::SPEC_PENDING || $this->codeQuality === self::QUALITY_PENDING);
    }

    public function canRevise(): bool
    {
        return $this->revisionCount < 3;
    }
}
