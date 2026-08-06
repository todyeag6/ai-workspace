<?php

declare(strict_types=1);

namespace App\Tests\Identity;

use App\Audit\AuditLog;
use App\Data\PasswordResetTokenRepository;
use App\Data\UserRepository;
use App\Identity\AuthService;
use App\Identity\PasswordHasher;
use App\Identity\SessionStore;
use App\Tests\TestCase;
use Predis\Client;
use RuntimeException;

/**
 * FR-IDENT-001 (MFA-ready credentials), FR-IDENT-003 (server-side sessions),
 * FR-IDENT-004 (lockout after five failures, durable across sessions) and
 * FR-AUD-001 (the login outcome is audited).
 *
 * These tests run against real MySQL AND real Redis. A mocked Redis would only
 * prove that AuthService emits a SETEX; what FR-IDENT-003 actually requires is
 * that the session lives OUTSIDE the PHP process, so a second AuthService -
 * standing in for the next request - can resolve the same identity. That is
 * only meaningful against a live shared store.
 *
 * Cheap argon2id parameters are used deliberately: the hashing algorithm is
 * already proven by tests/Identity/PasswordHasherTest.php, and production cost
 * parameters would add seconds per login attempt to a test that performs six.
 *
 * © AI WebScapes 2026
 */
final class AuthServiceTest extends TestCase
{
    private const PASSWORD = 'correct horse battery staple';
    private const TENANT = 1;

    private Client $redis;

    /** @var list<string> */
    private array $sessionKeys = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->redis = new Client(['host' => 'redis', 'port' => 6379]);
    }

    protected function tearDown(): void
    {
        foreach ($this->sessionKeys as $key) {
            $this->redis->del([$key]);
        }

        $this->sessionKeys = [];

        parent::tearDown();
    }

    public function test_lockout_after_five_failures(): void
    {
        $userId = $this->seedUser();
        $auth = $this->authService();

        for ($attempt = 1; $attempt <= 5; $attempt++) {
            self::assertFalse(
                $auth->attempt($this->emailOf($userId), 'wrong password'),
                sprintf('bad login %d must be refused', $attempt)
            );
        }

        self::assertSame(5, $this->columnInt($userId, 'failed_logins'), 'failed_logins must be durable');
        self::assertNotNull($this->columnString($userId, 'locked_until'), 'the account must be locked');

        // The 6th attempt presents the CORRECT password and must still fail:
        // the lock lives in the database, so it is not reset by a new service
        // instance (i.e. by a new request or a discarded session).
        self::assertFalse(
            $this->authService()->attempt($this->emailOf($userId), self::PASSWORD),
            'a correct password must be refused while the account is locked (FR-IDENT-004)'
        );
    }

    public function test_login_audits_outcome(): void
    {
        $userId = $this->seedUser();

        $this->authService()->attempt($this->emailOf($userId), 'wrong password');
        self::assertSame(1, $this->auditCount('auth.login', 'failure'), 'a failed login must be audited');

        $auth = $this->authService();
        self::assertTrue($auth->attempt($this->emailOf($userId), self::PASSWORD));
        $this->registerSession($auth->currentSessionId());

        self::assertSame(1, $this->auditCount('auth.login', 'success'), 'a successful login must be audited');
    }

    public function test_revoke_clears_identity(): void
    {
        $userId = $this->seedUser();
        $auth = $this->authService();

        self::assertTrue($auth->attempt($this->emailOf($userId), self::PASSWORD));
        $sessionId = $auth->currentSessionId();
        $this->registerSession($sessionId);

        self::assertSame($userId, $auth->currentUserId());
        self::assertNotNull($sessionId);

        $auth->revoke();

        self::assertNull($auth->currentUserId(), 'revoke() must clear the identity');
        self::assertNull($auth->currentSessionId());

        // Server-side revocation: the session is gone from Redis too, so a
        // stolen session id cannot be replayed by the next request.
        self::assertNull($this->sessionStore()->read($sessionId));
    }

    public function test_session_is_resolvable_by_a_second_request(): void
    {
        $userId = $this->seedUser();
        $auth = $this->authService();

        self::assertTrue($auth->attempt($this->emailOf($userId), self::PASSWORD));
        $sessionId = $auth->currentSessionId();
        $this->registerSession($sessionId);
        self::assertNotNull($sessionId);

        $subject = $this->sessionStore()->read($sessionId);

        self::assertNotNull($subject, 'FR-IDENT-003: the session must live server-side in Redis');
        self::assertSame($userId, $subject->userId());
        self::assertSame(self::TENANT, $subject->tenantId());
    }

    public function test_identity_is_mfa_aware(): void
    {
        $enrolled = $this->seedUser('JBSWY3DPEHPK3PXP');
        $auth = $this->authService();

        self::assertTrue($auth->attempt($this->emailOf($enrolled), self::PASSWORD));
        $this->registerSession($auth->currentSessionId());

        // FR-IDENT-001: the credential is MFA-ready - the enrolment is carried
        // on the authenticated subject even though the second factor is not
        // challenged yet.
        self::assertTrue($auth->currentSubject()?->mfaEnrolled(), 'mfa_secret must reach the subject');
    }

    public function test_successful_login_clears_the_failure_counter(): void
    {
        $userId = $this->seedUser();
        $auth = $this->authService();

        self::assertFalse($auth->attempt($this->emailOf($userId), 'wrong password'));
        self::assertSame(1, $this->columnInt($userId, 'failed_logins'));

        self::assertTrue($auth->attempt($this->emailOf($userId), self::PASSWORD));
        $this->registerSession($auth->currentSessionId());

        self::assertSame(0, $this->columnInt($userId, 'failed_logins'));
    }

    public function test_unknown_identity_is_refused_and_audited(): void
    {
        $auth = $this->authService();

        self::assertFalse($auth->attempt('nobody-' . bin2hex(random_bytes(4)) . '@example.test', self::PASSWORD));
        self::assertSame(1, $this->auditCount('auth.login', 'failure'));
    }

    public function test_password_reset_token_is_single_use(): void
    {
        $userId = $this->seedUser();
        $auth = $this->authService();

        $token = $auth->issuePasswordResetToken($userId);

        self::assertNotSame('', $token);
        self::assertSame($userId, $auth->consumePasswordResetToken($token), 'the first redemption succeeds');
        self::assertNull($auth->consumePasswordResetToken($token), 'a reset token must be single-use');
    }

    public function test_expired_password_reset_token_is_refused(): void
    {
        $userId = $this->seedUser();
        $auth = $this->authService();

        $token = $auth->issuePasswordResetToken($userId, -60);

        self::assertNull($auth->consumePasswordResetToken($token), 'an expired token must be refused');
    }

    private function authService(): AuthService
    {
        return new AuthService(
            new UserRepository($this->pdo, self::TENANT),
            new PasswordResetTokenRepository($this->pdo, self::TENANT),
            new PasswordHasher(self::CHEAP_HASH),
            $this->sessionStore(),
            new AuditLog($this->pdo)
        );
    }

    private function sessionStore(): SessionStore
    {
        return new SessionStore($this->redis, 900);
    }

    /**
     * Cheap-but-valid argon2id parameters. 8 MiB / 1 pass is far below policy
     * and is used ONLY here, where the property under test is the lockout
     * counter rather than the hash strength.
     */
    private const CHEAP_HASH = ['memory_cost' => 8192, 'time_cost' => 1, 'threads' => 1];

    private function seedUser(?string $mfaSecret = null): int
    {
        $hasher = new PasswordHasher(self::CHEAP_HASH);

        $statement = $this->pdo->prepare(
            'INSERT INTO users (tenant_id, email, password_hash, role, is_active, status, mfa_secret)'
            . ' VALUES (:tenant_id, :email, :password_hash, :role, 1, :status, :mfa_secret)'
        );

        if ($statement === false) {
            throw new RuntimeException('Unable to prepare the user fixture insert.');
        }

        $statement->execute([
            'tenant_id' => self::TENANT,
            'email' => 'p1t4-' . bin2hex(random_bytes(6)) . '@example.test',
            'password_hash' => $hasher->hash(self::PASSWORD),
            // The legacy users.role column is untouched by RBAC: authorisation
            // reads user_roles / role_permissions (see RbacPolicy).
            'role' => 'viewer',
            'status' => 'active',
            'mfa_secret' => $mfaSecret,
        ]);

        return (int) $this->pdo->lastInsertId();
    }

    private function emailOf(int $userId): string
    {
        $email = $this->columnString($userId, 'email');
        if ($email === null) {
            throw new RuntimeException(sprintf('User %d has no email.', $userId));
        }

        return $email;
    }

    private function columnInt(int $userId, string $column): int
    {
        $value = $this->columnString($userId, $column);

        return $value === null ? 0 : (int) $value;
    }

    /**
     * Reads one users column with raw PDO on purpose: a test that could only
     * observe the database through the class under test could not falsify it.
     * $column is a hard-coded literal at every call site, never input.
     */
    private function columnString(int $userId, string $column): ?string
    {
        $statement = $this->pdo->prepare(
            'SELECT ' . $column . ' FROM users WHERE id = :id'
        );

        if ($statement === false) {
            throw new RuntimeException('Unable to prepare the users probe.');
        }

        $statement->execute(['id' => $userId]);
        $value = $statement->fetchColumn();

        return is_scalar($value) ? (string) $value : null;
    }

    private function auditCount(string $event, string $outcome): int
    {
        $statement = $this->pdo->prepare(
            'SELECT COUNT(*) FROM audit_log WHERE tenant_id = :tenant_id'
            . ' AND event = :event AND outcome = :outcome'
        );

        if ($statement === false) {
            throw new RuntimeException('Unable to prepare the audit probe.');
        }

        $statement->execute(['tenant_id' => self::TENANT, 'event' => $event, 'outcome' => $outcome]);
        $count = $statement->fetchColumn();

        return is_scalar($count) ? (int) $count : 0;
    }

    private function registerSession(?string $sessionId): void
    {
        if ($sessionId !== null) {
            $this->sessionKeys[] = SessionStore::KEY_PREFIX . $sessionId;
        }
    }
}
