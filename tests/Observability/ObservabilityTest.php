<?php

declare(strict_types=1);

namespace App\Tests\Observability;

use App\Observability\Health;
use App\Tests\TestCase;
use Predis\Client;

/**
 * Operational health reporting (FR-OBS-001).
 *
 * FR-OBS-001 the platform must be able to report the status of its external
 * dependencies - at minimum the database and the cache/queue (Redis). A health
 * endpoint that only reports "the web process is up" is useless during an
 * incident: this reports each dependency it actually depends on, so an
 * operator can see at a glance which one is down.
 *
 * These tests talk to the REAL db and Redis at db / redis:6379 on purpose - a
 * mocked dependency would only prove that the class emits a key, not that the
 * check is wired to something real.
 *
 * © AI WebScapes 2026
 */
final class ObservabilityTest extends TestCase
{
    private Client $redis;

    protected function setUp(): void
    {
        parent::setUp();
        $this->redis = new Client(['host' => 'redis', 'port' => 6379]);
    }

    public function test_health_reports_dependencies(): void
    {
        $health = (new Health($this->pdo, $this->redis))->check();

        $this->assertArrayHasKey('db', $health, 'the database dependency is reported');
        $this->assertArrayHasKey('redis', $health, 'the Redis dependency is reported');
        $this->assertTrue($health['db']['ok'], 'db is reachable in the test stack');
        $this->assertTrue($health['redis']['ok'], 'redis is reachable in the test stack');
    }

    public function test_health_reports_db_failure(): void
    {
        // A subclass overrides the probe to simulate a down database, so the
        // test of Health's REPORTING (FR-OBS-001) is deterministic and does not
        // depend on a dead TCP endpoint that PDO refuses to construct.
        $health = (new class ($this->pdo, $this->redis) extends Health {
            protected function probeDb(): array
            {
                return ['ok' => false, 'error' => 'Connection refused (simulated)'];
            }
        })->check();

        $this->assertArrayHasKey('db', $health);
        $this->assertFalse($health['db']['ok'], 'a down database is reported as down');
        $this->assertArrayHasKey('error', $health['db']);
    }

    public function test_health_reports_redis_failure(): void
    {
        $down = new Client(['host' => '127.0.0.1', 'port' => 9, 'timeout' => 1]);
        $health = (new Health($this->pdo, $down))->check();

        $this->assertArrayHasKey('redis', $health);
        $this->assertFalse($health['redis']['ok'], 'a down Redis is reported as down');
        $this->assertArrayHasKey('error', $health['redis']);
    }
}
