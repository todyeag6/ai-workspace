<?php

declare(strict_types=1);

namespace App\Tests\Console;

use App\Agents\AgentRegistry;
use App\Agents\AgentResourceLocator;
use App\AI\AIGateway;
use App\AI\AIRequest;
use App\AI\ModelAdapter;
use App\AI\SchemaValidator;
use App\Audit\AuditLog;
use App\Console\AgentInvocationController;
use App\Identity\AuthService;
use App\Identity\LoginController;
use App\Identity\PasswordHasher;
use App\Identity\SessionStore;
use App\Manager\ManagerOrchestrator;
use App\Manager\ManagerReviewRepository;
use App\Manager\ManagerTaskRepository;
use App\Security\CsrfGuard;
use App\Security\RbacPolicy;
use App\Security\TenantAuthMiddleware;
use App\Tests\TestCase;
use App\Data\PasswordResetTokenRepository;
use App\Data\UserRepository;
use Predis\Client;
use RuntimeException;

/**
 * The invocation endpoint (FR-AGENT-002, FR-TOOL-002, AC-001/002/003, SEC-005).
 *
 * WHY EVERY DENIAL REASON GETS ITS OWN TEST. A single "403 when not allowed"
 * test would pass even if the four refusal paths were collapsed into one -
 * and they must NOT be collapsed, because they mean different things: no
 * session (authenticate), bad CSRF (re-fetch the form), no permission (ask an
 * admin), object unavailable (the id is wrong OR someone else's). The last pair
 * is the one that must stay indistinguishable, so it gets its own assertion.
 *
 * THE MODEL IS FAKED. A network call in a unit test would make the suite depend
 * on Ollama being up and on what a model happens to say; the property under
 * test is the AUTHORIZATION and AUDIT behaviour around the call, not the
 * model's output. The fake adapter follows the pattern established in
 * tests/AI/AIGatewayTest.php and tests/Eval/EvalHarnessTest.php.
 *
 * © AI WebScapes 2026
 */
final class AgentInvocationControllerTest extends TestCase
{
    private const TENANT = 1;
    private const PASSWORD = 'correct horse battery staple';

    /** @var array{memory_cost:int, time_cost:int, threads:int} */
    private const CHEAP_HASH = ['memory_cost' => 8192, 'time_cost' => 1, 'threads' => 1];

    private Client $redis;

    /** @var list<string> */
    private array $sessionKeys = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->redis = $this->redisClient();
    }

    protected function tearDown(): void
    {
        foreach ($this->sessionKeys as $key) {
            $this->redis->del([$key]);
        }

        $this->sessionKeys = [];

        parent::tearDown();
    }

    public function test_an_authorised_invocation_runs_the_agent_and_returns_task_status(): void
    {
        $agentId = $this->seedActiveAgent(self::TENANT, 'invoke-ok');
        [$sessionId, $csrf] = $this->signInWithRole('admin');

        $response = $this->controller(self::TENANT)->handle([
            'method' => 'POST',
            'path' => AgentInvocationController::PATH,
            'body' => [
                'agent_id' => (string) $agentId,
                'work_description' => 'Classify the inbound lead.',
                'csrf_token' => $csrf,
            ],
            'cookies' => [LoginController::COOKIE_NAME => $sessionId],
        ]);

        self::assertSame(200, $response['status'], (string) json_encode($response['body']));
        self::assertArrayHasKey('status', $response['body']);
        self::assertArrayHasKey('tasks', $response['body']);
    }

    public function test_no_session_is_refused_with_reason_no_session(): void
    {
        $agentId = $this->seedActiveAgent(self::TENANT, 'invoke-nosession');

        $response = $this->controller(self::TENANT)->handle([
            'method' => 'POST',
            'path' => AgentInvocationController::PATH,
            'body' => ['agent_id' => (string) $agentId, 'work_description' => 'x', 'csrf_token' => 'irrelevant'],
        ]);

        self::assertSame(403, $response['status']);
        self::assertSame(
            TenantAuthMiddleware::REASON_NO_SESSION,
            $response['body']['reason'] ?? null,
            'an unauthenticated call must be distinguishable as "authenticate"'
        );
    }

    public function test_a_missing_csrf_token_is_refused_with_reason_csrf(): void
    {
        $agentId = $this->seedActiveAgent(self::TENANT, 'invoke-nocsrf');
        [$sessionId] = $this->signInWithRole('admin');

        $response = $this->controller(self::TENANT)->handle([
            'method' => 'POST',
            'path' => AgentInvocationController::PATH,
            'body' => ['agent_id' => (string) $agentId, 'work_description' => 'x'],
            'cookies' => [LoginController::COOKIE_NAME => $sessionId],
        ]);

        self::assertSame(403, $response['status']);
        self::assertSame(TenantAuthMiddleware::REASON_CSRF, $response['body']['reason'] ?? null);
    }

    /**
     * A session that lacks agent.invoke - `staff` holds agent.console.view but
     * NOT agent.invoke (migration 024), which is exactly the distinction the
     * two codes were split for.
     */
    public function test_a_session_without_agent_invoke_is_refused_with_reason_forbidden(): void
    {
        $agentId = $this->seedActiveAgent(self::TENANT, 'invoke-forbidden');
        [$sessionId, $csrf] = $this->signInWithRole('staff');

        $response = $this->controller(self::TENANT)->handle([
            'method' => 'POST',
            'path' => AgentInvocationController::PATH,
            'body' => [
                'agent_id' => (string) $agentId,
                'work_description' => 'x',
                'csrf_token' => $csrf,
            ],
            'cookies' => [LoginController::COOKIE_NAME => $sessionId],
        ]);

        self::assertSame(403, $response['status']);
        self::assertSame(
            TenantAuthMiddleware::REASON_FORBIDDEN,
            $response['body']['reason'] ?? null,
            'staff may view the console but must not spend tokens by invoking'
        );
    }

    /**
     * AC-001. A foreign-tenant agent id and a non-existent id must produce the
     * SAME answer, or the endpoint enumerates other tenants' agent ids.
     */
    public function test_a_foreign_agent_and_a_missing_agent_are_indistinguishable(): void
    {
        $this->seedTenant(self::TENANT + 1);
        $foreignId = $this->seedActiveAgent(self::TENANT + 1, 'invoke-foreign');
        [$sessionId, $csrf] = $this->signInWithRole('admin');

        $body = static fn (string $id): array => [
            'agent_id' => $id,
            'work_description' => 'x',
            'csrf_token' => $csrf,
        ];

        $foreign = $this->controller(self::TENANT)->handle([
            'method' => 'POST',
            'path' => AgentInvocationController::PATH,
            'body' => $body((string) $foreignId),
            'cookies' => [LoginController::COOKIE_NAME => $sessionId],
        ]);

        $missing = $this->controller(self::TENANT)->handle([
            'method' => 'POST',
            'path' => AgentInvocationController::PATH,
            'body' => $body('999999999'),
            'cookies' => [LoginController::COOKIE_NAME => $sessionId],
        ]);

        self::assertSame(403, $foreign['status']);
        self::assertSame(403, $missing['status']);
        self::assertSame(
            $foreign['body'],
            $missing['body'],
            'AC-001: "not yours" and "does not exist" must be one answer'
        );
        self::assertNotSame(404, $foreign['status'], 'must not be a 404 - that distinguishes them');
    }

    /**
     * FR-AGENT-002: a disabled agent must not be runnable. It is in the caller's
     * own tenant, so a specific refusal leaks nothing across tenants.
     */
    public function test_a_disabled_agent_is_refused(): void
    {
        $agentId = $this->seedActiveAgent(self::TENANT, 'invoke-disabled');
        (new AgentRegistry($this->pdo, self::TENANT))->disable($agentId);
        [$sessionId, $csrf] = $this->signInWithRole('admin');

        $response = $this->controller(self::TENANT)->handle([
            'method' => 'POST',
            'path' => AgentInvocationController::PATH,
            'body' => [
                'agent_id' => (string) $agentId,
                'work_description' => 'x',
                'csrf_token' => $csrf,
            ],
            'cookies' => [LoginController::COOKIE_NAME => $sessionId],
        ]);

        self::assertSame(403, $response['status']);
        self::assertStringContainsString('not active', (string) ($response['body']['message'] ?? ''));
    }

    public function test_a_successful_invocation_is_audited(): void
    {
        $agentId = $this->seedActiveAgent(self::TENANT, 'invoke-audit');
        [$sessionId, $csrf] = $this->signInWithRole('admin');

        $this->controller(self::TENANT)->handle([
            'method' => 'POST',
            'path' => AgentInvocationController::PATH,
            'body' => [
                'agent_id' => (string) $agentId,
                'work_description' => 'Audit me.',
                'csrf_token' => $csrf,
            ],
            'cookies' => [LoginController::COOKIE_NAME => $sessionId],
        ]);

        $statement = $this->pdo->prepare(
            "SELECT COUNT(*) FROM audit_log
             WHERE tenant_id = :t AND event = 'agent.invoke' AND outcome = 'success'"
        );
        $statement->execute(['t' => self::TENANT]);

        self::assertGreaterThan(
            0,
            (int) $statement->fetchColumn(),
            'FR-AUD-001: a successful invocation must leave an audit record'
        );
    }

    public function test_a_non_post_method_returns_405(): void
    {
        $response = $this->controller(self::TENANT)->handle([
            'method' => 'GET',
            'path' => AgentInvocationController::PATH,
        ]);

        self::assertSame(405, $response['status']);
    }

    public function test_an_unknown_path_returns_404(): void
    {
        $response = $this->controller(self::TENANT)->handle([
            'method' => 'POST',
            'path' => '/console/other',
        ]);

        self::assertSame(404, $response['status']);
    }

    private function controller(int $tenantId): AgentInvocationController
    {
        $registry = new AgentRegistry($this->pdo, $tenantId);

        $middleware = new TenantAuthMiddleware(
            new SessionStore($this->redis, 900),
            new RbacPolicy($this->pdo),
            new AuditLog($this->pdo),
            new AgentResourceLocator($this->pdo),
            new CsrfGuard()
        );

        $gateway = new AIGateway($this->adapterAnsweringTheDeclaredSchema(), new SchemaValidator());

        $orchestrator = new ManagerOrchestrator(
            $registry,
            $gateway,
            'test-model',
            new ManagerTaskRepository($this->pdo, $tenantId),
            new ManagerReviewRepository($this->pdo, $tenantId)
        );

        return new AgentInvocationController(
            $middleware,
            $registry,
            $orchestrator,
            new AuditLog($this->pdo)
        );
    }

    /**
     * A deterministic, network-free model adapter (same pattern as
     * tests/AI/AIGatewayTest.php).
     *
     * It answers the schema the CALLER declared, rather than returning one
     * fixed JSON blob. That is what a model is asked to do, and it matters
     * here because the manager makes several calls with different schemas in
     * one run - TaskDecomposer wants `tasks`, ReviewLoop wants
     * `verdict`+`findings` - and SchemaValidator rejects unexpected keys. A
     * constant response would fail every call except the one it was shaped for,
     * which would test the fake rather than the controller.
     */
    private function adapterAnsweringTheDeclaredSchema(): ModelAdapter
    {
        return new class () implements ModelAdapter {
            public function generate(AIRequest $request): string
            {
                $payload = [];
                foreach ($request->outputSchema() as $key => $type) {
                    if (!is_string($key) || !is_string($type)) {
                        continue;
                    }

                    $payload[$key] = match (rtrim($type, '?')) {
                        'array' => [],
                        'int' => 1,
                        'float' => 1.0,
                        'bool' => true,
                        default => 'ok',
                    };
                }

                return (string) json_encode($payload);
            }
        };
    }

    /**
     * Logs in a real user holding the given role, returning the session id and
     * the session's CSRF token (read from the server-side record, exactly as a
     * rendered form would have been given it).
     *
     * @return array{0: string, 1: string}
     */
    private function signInWithRole(string $roleCode): array
    {
        $userId = $this->seedUser($roleCode);

        $login = new LoginController($this->authService(), new SessionStore($this->redis, 900));
        $response = $login->handle([
            'method' => 'POST',
            'path' => '/login',
            'body' => ['email' => $this->emailOf($userId), 'password' => self::PASSWORD],
        ]);

        self::assertSame(200, $response['status'], 'the sign-in fixture must succeed');

        $sessionId = (string) $response['body']['session_id'];
        $this->sessionKeys[] = SessionStore::KEY_PREFIX . $sessionId;

        $subject = (new SessionStore($this->redis, 900))->read($sessionId);
        self::assertNotNull($subject);

        return [$sessionId, $subject->csrfToken()];
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

    private function seedUser(string $roleCode): int
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
            'email' => 'invoke-' . bin2hex(random_bytes(6)) . '@example.test',
            'password_hash' => (new PasswordHasher(self::CHEAP_HASH))->hash(self::PASSWORD),
            'role' => 'viewer',
            'status' => 'active',
        ]);
        $userId = (int) $this->pdo->lastInsertId();

        $roles = $this->pdo->prepare('SELECT id FROM roles WHERE tenant_id = :t AND code = :c');
        if ($roles === false) {
            throw new RuntimeException('Unable to prepare the role lookup.');
        }
        $roles->execute(['t' => self::TENANT, 'c' => $roleCode]);
        $roleId = $roles->fetchColumn();
        if (!is_scalar($roleId)) {
            throw new RuntimeException(sprintf('Role "%s" is not seeded.', $roleCode));
        }

        $grant = $this->pdo->prepare(
            'INSERT INTO user_roles (tenant_id, user_id, role_id) VALUES (:t, :u, :r)'
        );
        if ($grant === false) {
            throw new RuntimeException('Unable to prepare the role grant.');
        }
        $grant->execute(['t' => self::TENANT, 'u' => $userId, 'r' => (int) $roleId]);

        return $userId;
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

    private function seedActiveAgent(int $tenantId, string $prefix): int
    {
        $this->seedTenant($tenantId);

        $registry = new AgentRegistry($this->pdo, $tenantId);
        $agentId = $registry->create(
            name: $prefix . '-' . bin2hex(random_bytes(4)),
            owner: 'test-owner',
            purpose: 'invocation test',
            systemPrompt: 'You are a test agent. Return JSON.',
            riskClass: 'low',
            allowedTools: [],
            modelConfig: ['model' => 'test-model']
        );
        $registry->activate($agentId, true);

        return $agentId;
    }

    private function seedTenant(int $tenantId): void
    {
        $statement = $this->pdo->prepare(
            'INSERT IGNORE INTO tenants (id, slug, name, status, deployment_model)'
            . ' VALUES (:id, :slug, :name, :status, :model)'
        );
        if ($statement === false) {
            throw new RuntimeException('Unable to prepare the tenant fixture.');
        }

        $statement->execute([
            'id' => $tenantId,
            'slug' => 'invoke-tenant-' . $tenantId,
            'name' => 'Invoke Tenant ' . $tenantId,
            'status' => 'active',
            'model' => 'cloud',
        ]);
    }
}
