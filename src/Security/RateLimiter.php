<?php

declare(strict_types=1);

namespace App\Security;

use Predis\ClientInterface;

/**
 * Fixed-window request throttle backed by shared Redis storage.
 *
 * LFR-CAP-003: the counter lives in Redis rather than in $_SESSION, so a
 * caller cannot reset their own allowance simply by discarding the session
 * cookie. Every request that presents the same identity - in practice the
 * HMAC of the client IP - lands on the same key regardless of session.
 *
 * The window is a fixed one, not a sliding one: the TTL is set once, when
 * INCR creates the key, and is deliberately NOT refreshed by later hits.
 * A blocked caller therefore always regains access within $windowSec of
 * their first request in the window instead of being locked out
 * indefinitely by continuing to hammer the endpoint.
 */
final class RateLimiter
{
    public function __construct(
        private ClientInterface $redis,
        private string $bucket,
        private int $max,
        private int $windowSec
    ) {
    }

    /**
     * Records one request against $key and reports whether it is allowed.
     *
     * INCR is atomic and creates the key at 1 when it is absent, so
     * concurrent requests cannot race past the limit by both reading a
     * stale count. EXPIRE is applied only on that first hit, which opens
     * the window.
     */
    public function hit(string $key): bool
    {
        $redisKey = "ratelimit:{$this->bucket}:{$key}";

        $count = (int) $this->redis->incr($redisKey);

        if ($count === 1) {
            $this->redis->expire($redisKey, $this->windowSec);
        }

        return $count <= $this->max;
    }
}
