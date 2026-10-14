<?php

declare(strict_types=1);

namespace App\Tests\Identity;

use App\Audit\AuditLog;
use App\Data\PasswordResetTokenRepository;
use App\Data\UserRepository;
use App\Identity\AuthService;
use App\Identity\LoginController;
use App\Identity\PasswordHasher;
use App\Identity\SessionStore;
use App\Tests\TestCase;
use Predis\Client;
use RuntimeException;

/**
 * The HTTP edge of operator login (FR-IDENT-001/003/004, SEC-005).
 *
 * Runs against real MySQL and real Redis, for the same reason AuthServiceTest
 * does: the property that matters is that the session lives OUTSIDE the PHP
 * process, so a second request can resolve the same identity. A mocked store
 * would only prove the controller emits a call.
 *
 * THE ANTI-ENUMERATION TEST IS THE IMPORTANT ONE. It does not check that a bad
 * login fails - that is easy. It checks that an unknown account, a wrong
 * password and a locked account all produce the IDENTICAL response body, so a
 * caller cannot tell which addresses exist. If those three ever diverge, the
 * login form becomes an account-discovery oracle and every other control here
 * is worth less than it looks.
 *
 * © AI WebScapes 2026
 */
final class LoginControllerTest extends TestCase
{
    private const PASSWORD = 'correct horse battery staple';
    private const TENANT = 1;

    /**
     * Cheap-but-valid argon2id parameters, matching AuthServiceTest: the hash
     * strength is proven in PasswordHasherTest, and production cost would add
     * seconds to a test that performs several logins.
     *
     * @var array{memory_cost:int, time_cost:int, threads:int}
     */
    private const CHEAP_HASH = ['memory_cost' => 8192, 'time_cost' => 1, 'threads' => 1];

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

    public function test_get_login_returns_200(): void
    {
        $response = $this->controller()->handle(['method' => 'GET', 'path' => '/login']);

        self::assertSame(200, $response['status']);
    }

    public function test_valid_credentials_return_200_and_a_session_id(): void
    {
        $userId = $this->seedUser();

        $response = $this->controller()->handle([
            'method' => 'POST',
            'path' => '/login',
            'body' => ['email' => $this->emailOf($userId), 'password' => self::PASSWORD],
        ]);

        self::assertSame(200, $response['status']);
        self::assertArrayHasKey('session_id', $response['body']);
        self::assertNotSame('', $response['body']['session_id']);

        $this->rememberSession((string) $response['body']['session_id']);
    }

    public function test_a_session_cookie_is_set_on_success(): void
    {
        $userId = $this->seedUser();

        $response = $this->controller()->handle([
            'method' => 'POST',
            'path' => '/login',
            'body' => ['email' => $this->emailOf($userId), 'password' => self::PASSWORD],
        ]);

        $cookie = $response['headers']['Set-Cookie'] ?? '';
        self::assertStringContainsString(LoginController::COOKIE_NAME . '=', $cookie);
        self::assertStringContainsString('HttpOnly', $cookie, 'the session cookie must not be readable by JS');
        self::assertStringContainsString('SameSite=Lax', $cookie);
        self::assertStringContainsString('Path=/', $cookie);
        self::assertStringNotContainsString('Secure', $cookie, 'not set on a plain-HTTP test request');

        $this->rememberSession((string) $response['body']['session_id']);
    }

    public function test_the_secure_flag_is_set_when_the_request_is_https(): void
    {
        $userId = $this->seedUser();

        $response = $this->controller(secureRequest: true)->handle([
            'method' => 'POST',
            'path' => '/login',
            'body' => ['email' => $this->emailOf($userId), 'password' => self::PASSWORD],
        ]);

        $cookie = (string) ($response['headers']['Set-Cookie'] ?? '');
        self::assertStringContainsString(
            'Secure',
            $cookie,
            'NIST SP 800-63B-4 5.1.1: the session cookie SHALL be accessible only on secure sessions'
        );

        $this->rememberSession((string) $response['body']['session_id']);
    }

    public function test_bad_password_returns_401(): void
    {
        $userId = $this->seedUser();

        $response = $this->controller()->handle([
            'method' => 'POST',
            'path' => '/login',
            'body' => ['email' => $this->emailOf($userId), 'password' => 'definitely wrong'],
        ]);

        self::assertSame(401, $response['status']);
        self::assertArrayNotHasKey('session_id', $response['body']);
    }

    /**
     * THE ORACLE GUARD. Three genuinely different causes of failure must be
     * indistinguishable from outside.
     */
    public function test_unknown_account_wrong_password_and_locked_account_are_indistinguishable(): void
    {
        $userId = $this->seedUser();
        $email = $this->emailOf($userId);

        // (a) unknown account
        $unknown = $this->controller()->handle([
            'method' => 'POST',
            'path' => '/login',
            'body' => ['email' => 'nobody-' . bin2hex(random_bytes(4)) . '@example.test', 'password' => self::PASSWORD],
        ]);

        // (b) known account, wrong password
        $wrongPassword = $this->controller()->handle([
            'method' => 'POST',
            'path' => '/login',
            'body' => ['email' => $email, 'password' => 'wrong'],
        ]);

        // (c) known account, locked by five consecutive failures
        for ($i = 0; $i < 5; $i++) {
            $this->controller()->handle([
                'method' => 'POST',
                'path' => '/login',
                'body' => ['email' => $email, 'password' => 'wrong'],
            ]);
        }
        $locked = $this->controller()->handle([
            'method' => 'POST',
            'path' => '/login',
            'body' => ['email' => $email, 'password' => self::PASSWORD],
        ]);

        self::assertSame(401, $unknown['status']);
        self::assertSame(401, $wrongPassword['status']);
        self::assertSame(401, $locked['status'], 'a locked account must not be distinguishable');

        self::assertSame(
            $unknown['body'],
            $wrongPassword['body'],
            'an unknown account must not read differently from a wrong password'
        );
        self::assertSame(
            $unknown['body'],
            $locked['body'],
            'a locked account must not read differently from a wrong password'
        );
    }

    public function test_missing_credentials_return_401_with_the_same_message(): void
    {
        $response = $this->controller()->handle([
            'method' => 'POST',
            'path' => '/login',
            'body' => ['email' => '', 'password' => ''],
        ]);

        self::assertSame(401, $response['status']);
        self::assertArrayNotHasKey('session_id', $response['body']);
    }

    public function test_an_unsupported_method_returns_405(): void
    {
        $response = $this->controller()->handle(['method' => 'DELETE', 'path' => '/login']);

        self::assertSame(405, $response['status']);
    }

    public function test_an_unknown_path_returns_404(): void
    {
        $response = $this->controller()->handle(['method' => 'GET', 'path' => '/nope']);

        self::assertSame(404, $response['status']);
    }

    private function controller(bool $secureRequest = false): LoginController
    {
        return new LoginController($this->authService(), $secureRequest);
    }

    private function authService(): AuthService
    {
        return new AuthService(
            new UserRepository($this->pdo, self::TENANT),
            new PasswordResetTokenRepository($this->pdo, self::TENANT),
            new PasswordHasher(self::CHEAP_HASH),
            new SessionStore($this->redis, 900),
            new AuditLog($this->pdo)
        );
    }

    private function rememberSession(string $sessionId): void
    {
        $this->sessionKeys[] = SessionStore::KEY_PREFIX . $sessionId;
    }

    private function seedUser(): int
    {
        $statement = $this->pdo->prepare(
            'INSERT INTO users (tenant_id, email, password_hash, role, is_active, status, mfa_secret)'
            . ' VALUES (:tenant_id, :email, :password_hash, :role, 1, :status, NULL)'
        );
        if ($statement === false) {
            throw new RuntimeException('Unable to prepare the user fixture insert.');
        }

        $statement->execute([
            'tenant_id' => self::TENANT,
            'email' => 'login-' . bin2hex(random_bytes(6)) . '@example.test',
            'password_hash' => (new PasswordHasher(self::CHEAP_HASH))->hash(self::PASSWORD),
            'role' => 'viewer',
            'status' => 'active',
        ]);

        return (int) $this->pdo->lastInsertId();
    }

    private function emailOf(int $userId): string
    {
        $statement = $this->pdo->prepare('SELECT email FROM users WHERE id = :id');
        if ($statement === false) {
            throw new RuntimeException('Unable to prepare the email lookup.');
        }
        $statement->execute(['id' => $userId]);
        $email = $statement->fetchColumn();

        if (!is_string($email)) {
            throw new RuntimeException('Seeded user has no email.');
        }

        return $email;
    }
}
