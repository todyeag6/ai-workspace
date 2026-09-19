<?php

declare(strict_types=1);

namespace App\Tests\Manager;

use App\Manager\ManagerTask;
use PHPUnit\Framework\TestCase;

final class ManagerTaskTest extends TestCase
{
    public function testTaskCreation(): void
    {
        $task = new ManagerTask(
            id: 1,
            tenantId: 1,
            workflowId: null,
            agentId: null,
            taskType: 'test',
            risk: 'low',
            status: 'pending',
            specCompliance: 'pending',
            codeQuality: 'pending',
            revisionCount: 0,
            context: [],
            result: null,
        );

        $this->assertSame(1, $task->id());
        $this->assertSame('test', $task->taskType());
        $this->assertFalse($task->requiresApproval());
    }

    public function testHighRiskRequiresApproval(): void
    {
        $task = new ManagerTask(
            id: 1,
            tenantId: 1,
            workflowId: null,
            agentId: null,
            taskType: 'test',
            risk: 'high',
            status: 'pending',
            specCompliance: 'pending',
            codeQuality: 'pending',
            revisionCount: 0,
            context: [],
            result: null,
        );

        $this->assertTrue($task->requiresApproval());
    }

    public function testCanRevise(): void
    {
        $task = new ManagerTask(
            id: 1,
            tenantId: 1,
            workflowId: null,
            agentId: null,
            taskType: 'test',
            risk: 'low',
            status: 'pending',
            specCompliance: 'pending',
            codeQuality: 'pending',
            revisionCount: 2,
            context: [],
            result: null,
        );

        $this->assertTrue($task->canRevise());
    }

    public function testCannotReviseAfterThreeAttempts(): void
    {
        $task = new ManagerTask(
            id: 1,
            tenantId: 1,
            workflowId: null,
            agentId: null,
            taskType: 'test',
            risk: 'low',
            status: 'pending',
            specCompliance: 'pending',
            codeQuality: 'pending',
            revisionCount: 3,
            context: [],
            result: null,
        );

        $this->assertFalse($task->canRevise());
    }

    public function testInvalidRiskThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new ManagerTask(
            id: 1,
            tenantId: 1,
            workflowId: null,
            agentId: null,
            taskType: 'test',
            risk: 'invalid',
            status: 'pending',
            specCompliance: 'pending',
            codeQuality: 'pending',
            revisionCount: 0,
            context: [],
            result: null,
        );
    }

    public function testIsPendingReview(): void
    {
        $task = new ManagerTask(
            id: 1,
            tenantId: 1,
            workflowId: null,
            agentId: null,
            taskType: 'test',
            risk: 'low',
            status: 'completed',
            specCompliance: 'pending',
            codeQuality: 'pending',
            revisionCount: 0,
            context: [],
            result: ['status' => 'done'],
        );

        $this->assertTrue($task->isPendingReview());
    }

    public function testIsPendingReviewWhenSpecDoneButQualityPending(): void
    {
        $task = new ManagerTask(
            id: 1,
            tenantId: 1,
            workflowId: null,
            agentId: null,
            taskType: 'test',
            risk: 'low',
            status: 'completed',
            specCompliance: 'pass',
            codeQuality: 'pending',
            revisionCount: 0,
            context: [],
            result: ['status' => 'done'],
        );

        $this->assertTrue($task->isPendingReview());
    }

    public function testIsNotPendingReviewWhenBothDone(): void
    {
        $task = new ManagerTask(
            id: 1,
            tenantId: 1,
            workflowId: null,
            agentId: null,
            taskType: 'test',
            risk: 'low',
            status: 'completed',
            specCompliance: 'pass',
            codeQuality: 'approved',
            revisionCount: 0,
            context: [],
            result: ['status' => 'done'],
        );

        $this->assertFalse($task->isPendingReview());
    }

    public function testCriticalRiskRequiresApproval(): void
    {
        $task = new ManagerTask(
            id: 1,
            tenantId: 1,
            workflowId: null,
            agentId: null,
            taskType: 'test',
            risk: 'critical',
            status: 'pending',
            specCompliance: 'pending',
            codeQuality: 'pending',
            revisionCount: 0,
            context: [],
            result: null,
        );

        $this->assertTrue($task->requiresApproval());
    }

    public function testLowRiskDoesNotRequireApproval(): void
    {
        $task = new ManagerTask(
            id: 1,
            tenantId: 1,
            workflowId: null,
            agentId: null,
            taskType: 'test',
            risk: 'low',
            status: 'pending',
            specCompliance: 'pending',
            codeQuality: 'pending',
            revisionCount: 0,
            context: [],
            result: null,
        );

        $this->assertFalse($task->requiresApproval());
    }

    public function testMediumRiskDoesNotRequireApproval(): void
    {
        $task = new ManagerTask(
            id: 1,
            tenantId: 1,
            workflowId: null,
            agentId: null,
            taskType: 'test',
            risk: 'medium',
            status: 'pending',
            specCompliance: 'pending',
            codeQuality: 'pending',
            revisionCount: 0,
            context: [],
            result: null,
        );

        $this->assertFalse($task->requiresApproval());
    }
}
