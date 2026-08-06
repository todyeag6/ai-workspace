<?php

declare(strict_types=1);

namespace App\Identity;

use App\Security\CsrfGuard;
use App\Security\Subject;
use Predis\ClientInterface;

/**
 * Server-side sessions in Redis (FR-IDENT-003).
 *
 * WHY NOT $_SESSION. PHP's default handler writes a file on the web node that
 * created it, which fails the moment there is more than one app container, and
 * it keys the record by a cookie the client also controls the lifetime of.
 * A Redis record with a server-set TTL is shared by every node and, crucially,
 * can be DESTROYED server-side - which is what makes revoke() (FR-IDENT-004)
 * and "log out everywhere" real rather than advisory.
 *
 * The session id is 32 random bytes from random_bytes(), hex-encoded: it is a
 * bearer credential, so it comes from the CSPRNG, never from uniqid() or
 * anything seeded by the clock.
 *
 * The payload carries the TENANT. That is what lets AC-001 hold: the tenant of
 * a request is read from a record only the server can write, never from a
 * parameter the caller can set.
 *
 * © AI WebScapes 2026
 */
final class SessionStore
{
    public const KEY_PREFIX = 'session:';

    private const ID_BYTES = 32;

    public function __construct(
        private ClientInterface $redis,
        private int $ttlSeconds = 3600
    ) {
    }

    /**
     * Creates a session and returns the authenticated subject holding its id.
     */
    public function start(int $tenantId, int $userId, bool $mfaEnrolled): Subject
    {
        $sessionId = bin2hex(random_bytes(self::ID_BYTES));

        $subject = new Subject($tenantId, $userId, $sessionId, CsrfGuard::newToken(), $mfaEnrolled);

        $payload = json_encode([
            'tenant_id' => $tenantId,
            'user_id' => $userId,
            'csrf' => $subject->csrfToken(),
            'mfa' => $mfaEnrolled,
        ]);

        // json_encode returns false only for unencodable input (resources,
        // NAN, malformed UTF-8). This array is four scalars, so the branch is
        // unreachable - handled rather than assumed so the class stays honest
        // under static analysis.
        if ($payload === false) {
            $payload = '{}';
        }

        $this->redis->setex(self::KEY_PREFIX . $sessionId, $this->ttlSeconds, $payload);

        return $subject;
    }

    /**
     * Resolves a session id to its subject, or null when the id is unknown,
     * expired, revoked or malformed. Every failure mode collapses to null: a
     * caller cannot tell a forged id from an expired one.
     */
    public function read(string $sessionId): ?Subject
    {
        if ($sessionId === '') {
            return null;
        }

        $raw = $this->redis->get(self::KEY_PREFIX . $sessionId);
        if (!is_string($raw) || $raw === '') {
            return null;
        }

        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            return null;
        }

        $tenantId = $decoded['tenant_id'] ?? null;
        $userId = $decoded['user_id'] ?? null;
        $csrf = $decoded['csrf'] ?? null;

        if (!is_int($tenantId) || !is_int($userId) || !is_string($csrf)) {
            return null;
        }

        if ($tenantId <= 0 || $userId <= 0) {
            return null;
        }

        return new Subject($tenantId, $userId, $sessionId, $csrf, ($decoded['mfa'] ?? false) === true);
    }

    /**
     * Server-side revocation: the record is deleted, so the id is dead for
     * every node immediately rather than when a cookie happens to expire.
     */
    public function destroy(string $sessionId): void
    {
        if ($sessionId === '') {
            return;
        }

        $this->redis->del([self::KEY_PREFIX . $sessionId]);
    }
}
