<?php

declare(strict_types=1);

namespace App\Tests\Security;

use App\Security\RateLimiter;
use PHPUnit\Framework\TestCase;
use Predis\Client;

/**
 * LFR-CAP-003: the demo-request throttle must live in shared storage rather
 * than in the PHP session, so that discarding a session cookie cannot reset
 * the counter.
 *
 * These tests talk to the REAL Redis at redis:6379 on purpose. A mocked client
 * would only prove that the class emits an INCR; the capability actually under
 * test is that two independent RateLimiter instances - standing in for two
 * separate requests, or for a request whose session was thrown away - observe
 * the same counter. That is only meaningful against a live shared store.
 *
 * Deliberately extends PHPUnit's TestCase - not App\Tests\TestCase - because
 * nothing here touches MySQL; the suite stays fast.
 *
 * Isolation: every test allocates its own random bucket, so no two tests, and
 * no two runs of the same test, can ever collide on a Redis key. That makes
 * the tests order-independent without flushing a shared dev database, and
 * tearDown() removes exactly the keys the test created.
 */
final class RateLimiterTest extends TestCase
{
    private Client $redis;

    /** @var list<string> */
    private array $buckets = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->redis = new Client(['host' => 'redis', 'port' => 6379]);
    }

    protected function tearDown(): void
    {
        foreach ($this->buckets as $bucket) {
            /** @var list<string> $keys */
            $keys = $this->redis->keys('ratelimit:' . $bucket . ':*');

            if ($keys !== []) {
                $this->redis->del($keys);
            }
        }

        parent::tearDown();
    }

    public function test_exceeding_limit_blocks(): void
    {
        $rl = new RateLimiter($this->redis, $this->uniqueBucket('pub:leads'), 3, 60);

        $this->assertTrue($rl->hit('1.2.3.4'));
        $this->assertTrue($rl->hit('1.2.3.4'));
        $this->assertTrue($rl->hit('1.2.3.4'));
        $this->assertFalse($rl->hit('1.2.3.4'), 'the 4th hit exceeds max=3 and must be blocked');
    }

    public function test_scopes_are_independent(): void
    {
        $rl = new RateLimiter($this->redis, $this->uniqueBucket('x'), 1, 60);

        $this->assertTrue($rl->hit('ipA'));
        $this->assertTrue($rl->hit('ipB'), 'a different key gets its own counter');
    }

    public function test_survives_session_loss(): void
    {
        $bucket = $this->uniqueBucket('y');

        $rl = new RateLimiter($this->redis, $bucket, 1, 60);
        $this->assertTrue($rl->hit('ipC'));

        // A brand new instance stands in for a request that lost its session.
        $fresh = new RateLimiter($this->redis, $bucket, 1, 60);
        $this->assertFalse($fresh->hit('ipC'), 'the count must survive session loss');
    }

    /**
     * Allocates a bucket nobody else can be using and registers it for cleanup.
     */
    private function uniqueBucket(string $label): string
    {
        $bucket = $label . ':' . bin2hex(random_bytes(6));
        $this->buckets[] = $bucket;

        return $bucket;
    }
}
