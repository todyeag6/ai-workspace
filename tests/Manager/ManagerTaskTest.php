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
            1, 1, null, null, 'test', 'low',
            'pending', 'pending', 'pending', 0, [], null,
        );

        $this->assertSame(1, $task->id());
        $this->assertSame('test', $task->taskType());
        $this->assertFalse($task->requiresApproval());
    }

    public function testHighRiskRequiresApproval(): void
    {
        $task = new ManagerTask(
            1, 1, null, null, 'test', 'high',
            'pending', 'pending', 'pending', 0, [], null,
        );

        $this->assertTrue($task->requiresApproval());
    }

    public function testCanRevise(): void
    {
        $task = new ManagerTask(
            1, 1, null, null, 'test', 'low',
            'pending', 'pending', 'pending', 2, [], null,
        );

        $this->assertTrue($task->canRevise());
    }

    public function testCannotReviseAfterThreeAttempts(): void
    {
        $task = new ManagerTask(
            1, 1, null, null, 'test', 'low',
            'pending', 'pending', 'pending', 3, [], null,
        );

        $this->assertFalse($task->canRevise());
    }

    public function testInvalidRiskThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new ManagerTask(
            1, 1, null, null, 'test', 'invalid',
            'pending', 'pending', 'pending', 0, [], null,
        );
    }

    public function testIsPendingReview(): void
    {
        $task = new ManagerTask(
            1, 1, null, null, 'test', 'low',
            'completed', 'pending', 'pending', 0, [], ['done'],
        );

        $this->assertTrue($task->isPendingReview());
    }

    public function testIsPendingReviewWhenSpecDoneButQualityPending(): void
    {
        $task = new ManagerTask(
            1, 1, null, null, 'test', 'low',
            'completed', 'pass', 'pending', 0, [], ['done'],
        );

        $this->assertTrue($task->isPendingReview());
    }

    public function testIsNotPendingReviewWhenBothDone(): void
    {
        $task = new ManagerTask(
            1, 1, null, null, 'test', 'low',
            'completed', 'pass', 'approved', 0, [], ['done'],
        );

        $this->assertFalse($task->isPendingReview());
    }


    public function testCriticalRiskRequiresApproval(): void
    {
        $task = new ManagerTask(
            1, 1, null, null, 'test', 'critical',
            'pending', 'pending', 'pending', 0, [], null,
        );

        $this->assertTrue($task->requiresApproval());
    }

    public function testLowRiskDoesNotRequireApproval(): void
    {
        $task = new ManagerTask(
            1, 1, null, null, 'test', 'low',
            'pending', 'pending', 'pending', 0, [], null,
        );

        $this->assertFalse($task->requiresApproval());
    }

    public function testMediumRiskDoesNotRequireApproval(): void
    {
        $task = new ManagerTask(
            1, 1, null, null, 'test', 'medium',
            'pending', 'pending', 'pending', 0, [], null,
        );

        $this->assertFalse($task->requiresApproval());
    }
}
