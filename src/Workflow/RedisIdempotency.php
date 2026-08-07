<?php

declare(strict_types=1);

namespace App\Workflow;

use Predis\ClientInterface;

/**
 * FR-ORCH-002: a single-use claim on an idempotency key, backed by Redis
 * SET ... EX ... NX.
 *
 * WHY NX AND NOT "EXISTS then SET": the two-step form has a window between the
 * read and the write in which a concurrent retry - a user double-click, a
 * queue redelivery, two workers on the same message - also reads "absent" and
 * also proceeds. Both then send the email or take the payment. SET NX resolves
 * the race inside Redis: exactly one caller is told the key was free.
 *
 * WHY THE CLAIM COMES BEFORE THE EFFECT, NEVER AFTER: claiming afterwards means
 * a crash between the effect and the claim leaves the key unclaimed, and the
 * retry repeats a charge that already happened. Claiming first can at worst
 * lose an effect that never ran, which is recoverable by an operator - the
 * other ordering is not recoverable by anyone.
 *
 * WHY A TTL AND NOT A PERMANENT KEY: keys are unbounded in number and each one
 * is only interesting for as long as a retry might arrive. An hour by default,
 * and callers who need a longer replay window pass their own.
 *
 * STATED LIMIT: this is at-most-once, not exactly-once. If the process dies
 * after the claim and before the effect, the effect is lost and the retry is
 * refused. That is the deliberate trade for money-moving steps - a lost email
 * is a support ticket, a duplicated refund is a loss.
 *
 * © AI WebScapes 2026
 */
final class RedisIdempotency
{
    /**
     * @param string $namespace Key prefix. Separating suites, tenants or
     *                          environments here keeps one caller's claims from
     *                          silencing another's effects, since Redis is
     *                          shared and is not rolled back by a transaction.
     */
    public function __construct(
        private ClientInterface $redis,
        private string $namespace = 'workflow:idem'
    ) {
    }

    /**
     * Attempts to claim $key.
     *
     * @return bool true when the key was free and is now held by this caller -
     *              the caller MAY perform the effect. false when it was already
     *              claimed: the effect has happened (or is happening) and this
     *              call must skip it.
     */
    public function claim(string $key, int $ttlSeconds = 3600): bool
    {
        $result = $this->redis->set(
            $this->namespace . ':' . $key,
            'claimed',
            'EX',
            $ttlSeconds,
            'NX'
        );

        // Predis answers a Status ('OK') when NX set the key and null when the
        // key already existed. Anything non-null means we hold the claim.
        return $result !== null;
    }
}
