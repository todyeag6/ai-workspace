<?php

declare(strict_types=1);

namespace App\Identity;

use App\Audit\AuditLog;
use App\Data\PasswordResetTokenRepository;
use App\Data\UserRepository;
use App\Security\Subject;

/**
 * Password authentication, server-side sessions, lockout and password reset
 * tokens for ONE tenant.
 *
 * FR-IDENT-001 MFA-ready:   the users.mfa_secret enrolment is read at login and
 *                           carried onto the Subject. The second factor is not
 *                           challenged yet - what matters now is that nothing
 *                           downstream has to be re-plumbed when it is.
 * FR-IDENT-003 sessions:    identity lives in Redis via SessionStore, not in
 *                           $_SESSION, so it is shared across app containers
 *                           and can be destroyed server-side.
 * FR-IDENT-004 lockout:     five bad attempts lock the account for
 *                           LOCKOUT_SECONDS. The counter and the expiry are
 *                           COLUMNS, so a new session, a new process or a
 *                           restart does not clear them - the sixth attempt is
 *                           refused even when the password is correct.
 * FR-AUD-001 audit:         every outcome, success or failure, is recorded.
 *
 * WHY THE SERVICE IS TENANT-BOUND. It takes repositories, not a PDO, and those
 * repositories cannot exist without a tenant. Login is therefore a question
 * asked inside one tenant - which it has to be, because (tenant_id, email) is
 * the unique key and the same address may exist in two tenants (AC-001).
 *
 * © AI WebScapes 2026
 */
final class AuthService
{
    /** FR-IDENT-004: the fifth consecutive failure locks the account. */
    public const MAX_FAILURES = 5;

    /** How long a lock lasts. Long enough to defeat online guessing. */
    public const LOCKOUT_SECONDS = 900;

    private const RESET_TOKEN_BYTES = 32;
    private const RESET_TTL_SECONDS = 3600;
    private const MYSQL_DATETIME = 'Y-m-d H:i:s';

    private ?Subject $subject = null;

    public function __construct(
        private UserRepository $users,
        private PasswordResetTokenRepository $resetTokens,
        private PasswordHasher $hasher,
        private SessionStore $sessions,
        private AuditLog $audit
    ) {
    }

    /**
     * Authenticates a credential and, on success, opens a server-side session.
     *
     * Returns a bare bool: the caller is told whether it worked and nothing
     * else. "No such account", "wrong password", "locked" and "disabled" are
     * one answer, because distinguishing them enumerates accounts. The
     * distinction is written to the audit trail, where the operator can see it
     * and the attacker cannot.
     */
    public function attempt(string $email, string $password): bool
    {
        $tenantId = $this->users->tenantId();
        $user = $this->users->findByEmail($email);

        if ($user === null) {
            // Hash anyway. Returning early here would make an unknown address
            // measurably faster than a known one, which is a free account
            // enumeration oracle over enough samples.
            $this->hasher->hash($password);
            $this->audit->loginFailed($tenantId, null, 'unknown identity');

            return false;
        }

        if ($user->isLocked(time())) {
            $this->audit->loginFailed($tenantId, $user->id(), 'account locked');

            return false;
        }

        if (!$user->canAuthenticate()) {
            $this->audit->loginFailed($tenantId, $user->id(), 'account not active');

            return false;
        }

        if (!$this->hasher->verify($password, $user->passwordHash())) {
            $this->registerFailure($user);
            $this->audit->loginFailed($tenantId, $user->id(), 'bad credentials');

            return false;
        }

        if ($this->hasher->needsRehash($user->passwordHash())) {
            // FR-IDENT-002: the only moment the plain text is available is the
            // only moment a cost upgrade can happen.
            $this->users->updatePasswordHash($user->id(), $this->hasher->hash($password));
        }

        $this->users->recordSuccessfulLogin($user->id(), date(self::MYSQL_DATETIME));
        $this->subject = $this->sessions->start($tenantId, $user->id(), $user->mfaEnrolled());
        $this->audit->loginSucceeded($tenantId, $user->id());

        return true;
    }

    /**
     * Adopts an existing session id, e.g. one arriving on a cookie.
     */
    public function resume(string $sessionId): bool
    {
        $this->subject = $this->sessions->read($sessionId);

        return $this->subject !== null;
    }

    public function currentSubject(): ?Subject
    {
        return $this->subject;
    }

    public function currentUserId(): ?int
    {
        return $this->subject?->userId();
    }

    public function currentSessionId(): ?string
    {
        return $this->subject?->sessionId();
    }

    /**
     * FR-IDENT-004: revocation. The session record is DELETED server-side, so
     * the id is dead for every container at once - not merely forgotten by
     * this process, which would leave a stolen cookie working.
     */
    public function revoke(): void
    {
        if ($this->subject !== null) {
            $this->sessions->destroy($this->subject->sessionId());
        }

        $this->subject = null;
    }

    /**
     * Issues a single-use password reset token and returns the plain value -
     * the ONLY time it exists in plaintext. Only its SHA-256 is stored.
     *
     * $ttlSeconds is injectable so expiry can be tested without waiting; the
     * negative value a test passes simply produces an already-expired token.
     */
    public function issuePasswordResetToken(int $userId, int $ttlSeconds = self::RESET_TTL_SECONDS): string
    {
        $token = bin2hex(random_bytes(self::RESET_TOKEN_BYTES));

        $this->resetTokens->issue(
            $userId,
            hash('sha256', $token),
            date(self::MYSQL_DATETIME, time() + $ttlSeconds)
        );

        return $token;
    }

    /**
     * Redeems a reset token exactly once, returning the user it belongs to, or
     * null when it is unknown, expired or already spent.
     */
    public function consumePasswordResetToken(string $token): ?int
    {
        if ($token === '') {
            return null;
        }

        return $this->resetTokens->consume(hash('sha256', $token), date(self::MYSQL_DATETIME));
    }

    /**
     * Increments the durable failure counter and locks the account on the
     * threshold. users.status is deliberately left alone: the lock is an
     * expiry, and writing 'locked' into a column with no expiry would need a
     * second mechanism to ever clear it.
     */
    private function registerFailure(UserRecord $user): void
    {
        $failures = $user->failedLogins() + 1;

        $lockedUntil = $failures >= self::MAX_FAILURES
            ? date(self::MYSQL_DATETIME, time() + self::LOCKOUT_SECONDS)
            : null;

        $this->users->recordFailedLogin($user->id(), $failures, $lockedUntil);
    }
}
