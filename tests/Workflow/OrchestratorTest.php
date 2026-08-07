<?php

declare(strict_types=1);

namespace App\Tests\Workflow;

use App\AI\ActionAuthority;
use App\Tests\TestCase;
use App\Workflow\Orchestrator;
use App\Workflow\RedisIdempotency;
use Predis\Client;

/**
 * FR-ORCH-001 (compensation), FR-ORCH-002 (idempotent retry) and FR-ORCH-003
 * (approval-gated high impact, the orchestration-level face of FR-AI-006).
 *
 * These tests use the REAL Redis at redis:6379, like RateLimiterTest: the
 * whole claim is "SET NX makes a replay effect-free", and a mocked client
 * would be asserting that the test author understands NX, not that Redis does.
 *
 * EVERY RUN GETS A FRESH KEY NAMESPACE. Redis is not rolled back by the
 * per-test transaction, so a fixed key would be claimed by the FIRST ever run
 * of the suite and every later run would see "already claimed" and skip the
 * action it is trying to count. tearDown() deletes the namespace as well.
 *
 * © AI WebScapes 2026
 */
final class OrchestratorTest extends TestCase
{
    private Client $redis;

    private RecordingEffector $external;

    private string $namespace;

    protected function setUp(): void
    {
        parent::setUp();

        $this->redis = new Client(['host' => 'redis', 'port' => 6379]);
        $this->namespace = 'test:orch:' . bin2hex(random_bytes(8));
        $this->external = new RecordingEffector();
    }

    protected function tearDown(): void
    {
        $keys = $this->redis->keys($this->namespace . ':*');
        if ($keys !== []) {
            $this->redis->del($keys);
        }

        parent::tearDown();
    }

    private function orchestrator(): Orchestrator
    {
        return new Orchestrator(
            $this->pdo,
            new RedisIdempotency($this->redis, $this->namespace),
            $this->external,
            new ActionAuthority()
        );
    }

    public function test_retry_does_not_duplicate_external_action(): void
    {
        $orchestrator = $this->orchestrator();

        $orchestrator->run('wf1', [['type' => 'send_email']], 'k1');
        $orchestrator->run('wf1', [['type' => 'send_email']], 'k1');

        self::assertSame(1, $this->external->sendCount);
    }

    public function test_high_risk_waits_for_approval(): void
    {
        $orchestrator = $this->orchestrator();
        $steps = [['type' => 'refund', 'risk' => 'high']];

        $orchestrator->run('wf2', $steps);
        self::assertFalse($this->external->refundCalled);

        $orchestrator->approve('wf2', 7);
        $orchestrator->run('wf2', $steps);

        self::assertTrue($this->external->refundCalled);
    }

    public function test_failed_step_runs_compensating_action(): void
    {
        $this->orchestrator()->run('wf3', [['type' => 'charge'], ['type' => 'fail']]);

        self::assertTrue($this->external->refundIssued);
        self::assertSame(1, $this->external->chargeCount);
    }

    public function test_low_risk_executes_without_approval(): void
    {
        $this->orchestrator()->run('wf4', [
            ['type' => 'send_email', 'risk' => 'low'],
            ['type' => 'refund', 'risk' => 'low'],
        ]);

        self::assertSame(1, $this->external->sendCount);
        self::assertTrue($this->external->refundCalled);
    }

    public function test_approval_required_blocks_critical(): void
    {
        $this->orchestrator()->run('wf5', [['type' => 'refund', 'risk' => 'critical']]);

        self::assertFalse($this->external->refundCalled);
    }

    public function test_idempotency_key_absent_still_safe(): void
    {
        $orchestrator = $this->orchestrator();
        $steps = [['type' => 'send_email']];

        $orchestrator->run('wf6', $steps);
        $orchestrator->run('wf6', $steps);

        self::assertSame(1, $this->external->sendCount);
    }
}
