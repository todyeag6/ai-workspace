<?php

declare(strict_types=1);

namespace App\Tests\Workflow;

use App\Workflow\WorkflowBuilder;
use App\Workflow\WorkflowDefinition;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

/**
 * P2-T3 workflow builder - the definition/validation seam the P1-T9 engine
 * lacked.
 *
 * The regression value is in the refusal tests: each invariant the engine
 * relies on (known step types, valid risk classes, high-impact needs approval,
 * distinct step types) is proven to be caught at authoring, so a malformed
 * workflow can never reach the money-moving Orchestrator::run().
 *
 * © AI WebScapes 2026
 */
final class WorkflowBuilderTest extends TestCase
{
    public function test_builds_a_valid_low_risk_workflow(): void
    {
        $def = (new WorkflowBuilder('wf-1', [
            ['type' => 'reserve_stock', 'risk' => 'low'],
        ]))->build();

        self::assertInstanceOf(WorkflowDefinition::class, $def);
        self::assertSame('wf-1', $def->workflowId);
        self::assertFalse($def->requiresApproval);
        self::assertSame([['type' => 'reserve_stock', 'risk' => 'low']], $def->steps());
    }

    public function test_normalises_risk_case_and_default(): void
    {
        $def = (new WorkflowBuilder('wf-2', [
            ['type' => 'charge'],
            ['type' => 'reserve_stock', 'risk' => 'LOW'],
        ]))->build();

        // charge defaults to 'low'; 'LOW' is normalised to 'low'. Neither is
        // high-impact, so no approval required.
        self::assertSame('low', $def->steps()[0]['risk']);
        self::assertSame('low', $def->steps()[1]['risk']);
        self::assertFalse($def->requiresApproval);
    }

    public function test_high_impact_flags_requires_approval(): void
    {
        $def = (new WorkflowBuilder('wf-3', [
            ['type' => 'charge', 'risk' => 'high'],
        ]))->build();

        self::assertTrue($def->requiresApproval);
    }

    public function test_rejects_unknown_step_type(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unknown workflow step type "wire_transfer"');

        (new WorkflowBuilder('wf-4', [['type' => 'wire_transfer']]))->build();
    }

    public function test_rejects_unknown_risk_class(): void
    {
        // The engine treats an unknown risk as 'high' (fail-closed); the builder
        // refuses the misspelling so the author sees their error instead of a
        // silent escalation.
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unknown risk class "higg"');

        (new WorkflowBuilder('wf-5', [['type' => 'charge', 'risk' => 'higg']]))->build();
    }

    public function test_rejects_duplicate_non_trigger_step_type(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Duplicate step type "charge"');

        (new WorkflowBuilder('wf-6', [
            ['type' => 'charge', 'risk' => 'high'],
            ['type' => 'charge', 'risk' => 'high'],
        ]))->build();
    }

    public function test_rejects_empty_workflow(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('at least one step');

        (new WorkflowBuilder('wf-7', []))->build();
    }

    public function test_rejects_empty_workflow_id(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('non-empty workflow id');

        (new WorkflowBuilder('', [['type' => 'reserve_stock']]))->build();
    }
}
