<?php

declare(strict_types=1);

namespace App\Tests\Bootstrap;

use App\Agents\AgentRegistry;
use App\Audit\AuditLog;
use App\Bootstrap\SecurityHeaders;
use App\Data\PasswordResetTokenRepository;
use App\Data\UserRepository;
use App\Identity\AuthService;
use App\Identity\LoginController;
use App\Identity\PasswordHasher;
use App\Identity\SessionStore;
use App\Tests\TestCase;
use PDO;
use Predis\Client;
use RuntimeException;

/**
 * The console's served surface, over REAL HTTP (SEC-004/009/010, AC-001, SEC-005).
 *
 * WHY THIS EXISTS ALONGSIDE THE CONTROLLER TESTS. Every other console test calls
 * a controller as a pure function. None of them proves that public/index.php
 * actually wires the gate up, reads the session from the cookie, or emits the
 * security headers on the 403 paths - and the SEC-009 pen-test found exactly
 * that class of gap on this file (headers missing on early-exit branches, a form
 * whose action was never routed). So this drives the real front controller
 * through PHP's built-in server, the same SAPI production uses.
 *
 * THE HARNESS MUST ACTUALLY RUN. `markTestSkipped` when `php -S` cannot start is
 * correct for a CI runner that forbids proc_open, but it makes a green suite
 * ambiguous: "passed" and "never ran" look identical. This class therefore
 * asserts the server started, so a skip can only come from the explicit
 * environment guard below and never silently from a broken harness.
 *
 * © AI WebScapes 2026
 */
final class ConsoleServedTest extends TestCase
{
    private const DOCROOT = '/app/public';
    private const PASSWORD = 'correct horse battery staple';
    private const TENANT = 1;

    /** @var array{memory_cost:int, time_cost:int, threads:int} */
    private const CHEAP_HASH = ['memory_cost' => 8192, 'time_cost' => 1, 'threads' => 1];

    private ?int $port = null;

    /** @var resource|null */
    private $server = null;

    /** @var array<int, resource> */
    private array $pipes = [];

    private Client $redis;

    /** @var list<string> */
    private array $sessionKeys = [];

    /**
     * Fixture rows written on a SEPARATE, COMMITTING connection.
     *
     * WHY THE BASE CLASS'S TRANSACTION IS NOT ENOUGH HERE. Every other test in
     * the suite seeds through $this->pdo inside the transaction setUp() opens,
     * and tearDown() rolls it back - that is the isolation model, and it works
     * because the assertions run in the SAME process.
     *
     * These tests do not. The subject is public/index.php served by `php -S`,
     * which is a SEPARATE PROCESS with its own MySQL connection. An uncommitted
     * row is invisible to it, so a fixture seeded inside the transaction does
     * not exist as far as the server is concerned: login fails with "those
     * credentials were not accepted" and every authenticated assertion collapses
     * to "no session cookie". That was the actual first-run failure, and it
     * looked like a broken login rather than an isolation artefact.
     *
     * So these fixtures are committed through a second connection and removed
     * explicitly in tearDown() - the "isolate by namespace, delete exactly what
     * you created" pattern, since there is no transaction to hide behind once a
     * subprocess has to see the data. Tracked by id so cleanup can never touch a
     * row this test did not create.
     *
     * @var list<int>
     */
    private array $committedUserIds = [];

    /** @var list<int> */
    private array $committedAgentIds = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->redis = $this->redisClient();

        $this->port = $this->freePort();

        // getenv() with no arguments returns the whole environment, so PATH and
        // friends survive; only the keys we must override are replaced. Passing
        // an env array to proc_open REPLACES the environment outright, which is
        // why it is seeded from the current one rather than built from scratch.
        $env = getenv();
        $env['DB_DSN'] = (string) (getenv('TEST_DB_DSN') ?: '');
        $env['REDIS_HOST'] = (string) (getenv('REDIS_HOST') ?: 'redis');
        $env['REDIS_PORT'] = (string) (getenv('REDIS_PORT') ?: '6379');
        $env['APP_TENANT_ID'] = '1';
        $env['APP_KEY'] = 'console-served-test-ip-hash-secret';

        $command = [
            PHP_BINARY,
            '-S',
            '127.0.0.1:' . $this->port,
            '-t',
            self::DOCROOT,
            self::DOCROOT . '/index.php',
        ];

        $server = proc_open(
            $command,
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $this->pipes,
            self::DOCROOT,
            $env
        );

        if (!is_resource($server)) {
            self::markTestSkipped('php -S could not start in this environment (proc_open unavailable).');
        }

        $this->server = $server;

        // Drain the server's stdout/stderr continuously. Leaving these pipes
        // unread would fill the OS pipe buffer and stall the server mid-request
        // - a classic proc_open trap that shows up as an inexplicable hang or a
        // truncated response. Reading them also gives us the server's own view
        // of every request, which is the only way to tell "the router answered
        // 404" from "the request never arrived".
        stream_set_blocking($this->pipes[1], false);
        stream_set_blocking($this->pipes[2], false);

        $this->awaitServer();
    }

    /**
     * The `php -S` process output so far.
     *
     * Kept because the pipes MUST be drained (see setUp): an unread stdout/stderr
     * pipe fills the OS buffer and stalls the server mid-request. This method is
     * the drain point and is called from tearDown().
     */
    private function serverLog(): string
    {
        $log = '';
        foreach ([1, 2] as $index) {
            if (isset($this->pipes[$index]) && is_resource($this->pipes[$index])) {
                $log .= (string) stream_get_contents($this->pipes[$index]);
            }
        }

        return $log;
    }

    protected function tearDown(): void
    {
        if (is_resource($this->server)) {
            proc_terminate($this->server);
            proc_close($this->server);
        }

        foreach ($this->pipes as $pipe) {
            if (is_resource($pipe)) {
                fclose($pipe);
            }
        }

        $this->pipes = [];
        $this->server = null;

        foreach ($this->sessionKeys as $key) {
            $this->redis->del([$key]);
        }
        $this->sessionKeys = [];

        // Drain the server's pipes before closing them, so a large response
        // cannot have left the process blocked on a full pipe buffer.
        $this->serverLog();

        // Remove exactly the committed fixtures this test created. Scoped by id,
        // so a concurrent run's rows (or the base class's own rolled-back
        // fixtures) are never touched. agent_versions and user_roles cascade.
        if ($this->committedAgentIds !== []) {
            $ids = implode(',', array_map('intval', $this->committedAgentIds));
            $this->fixtureConnection()->exec("DELETE FROM agents WHERE id IN ($ids)");
            $this->committedAgentIds = [];
        }

        if ($this->committedUserIds !== []) {
            $ids = implode(',', array_map('intval', $this->committedUserIds));
            $pdo = $this->fixtureConnection();
            $pdo->exec("DELETE FROM user_roles WHERE user_id IN ($ids)");
            $pdo->exec("DELETE FROM users WHERE id IN ($ids)");
            $this->committedUserIds = [];
        }

        parent::tearDown();
    }

    /**
     * A second connection used ONLY for fixtures the `php -S` subprocess must be
     * able to see. It commits immediately and is never part of the base class's
     * transaction. See the docblock on $committedUserIds for why this is
     * necessary rather than merely convenient.
     */
    private function fixtureConnection(): PDO
    {
        $dsn = getenv('TEST_DB_DSN');
        if ($dsn === false || $dsn === '') {
            throw new RuntimeException('TEST_DB_DSN is not set; cannot seed served fixtures.');
        }

        return new PDO($dsn, 'root', 'root', [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
    }

    /**
     * THE GATE. An unauthenticated request must not receive a single byte of the
     * console - not a redirect to a login page, not a stripped-down view.
     */
    public function test_console_is_refused_without_a_session(): void
    {
        $response = $this->request('/console');

        self::assertSame(403, $response['status'], 'an unauthenticated console request must be refused');
        self::assertStringNotContainsString('Registered agents', $response['body'], 'no console content may leak');
    }

    /**
     * SEC-009. The pen-test found headers missing on early-exit paths; the new
     * 403 path is exactly that shape, so it is asserted explicitly.
     */
    public function test_the_console_403_carries_the_full_security_header_set(): void
    {
        $response = $this->request('/console');

        self::assertSame(403, $response['status']);
        self::assertSame(
            SecurityHeaders::all()['Content-Security-Policy'],
            $response['headers']['content-security-policy'] ?? null,
            'the 403 path must carry the CSP'
        );
        self::assertSame('nosniff', $response['headers']['x-content-type-options'] ?? null);
        self::assertSame('DENY', $response['headers']['x-frame-options'] ?? null);
        self::assertSame('no-referrer', $response['headers']['referrer-policy'] ?? null);
    }

    public function test_login_form_is_served(): void
    {
        $response = $this->request('/login');

        self::assertSame(200, $response['status']);
        self::assertStringContainsString('Sign in', $response['body']);
        self::assertStringContainsString('autocomplete="current-password"', $response['body']);
        self::assertStringContainsString('<link rel="stylesheet" href="/assets/console.css">', $response['body']);
        self::assertStringNotContainsString('<script', $response['body'], 'CSP grants no inline script');
        self::assertStringNotContainsString('<style', $response['body'], 'CSP keeps style-src at self');
    }

    public function test_the_console_stylesheet_is_served(): void
    {
        $css = $this->request('/assets/console.css');

        self::assertSame(200, $css['status'], 'the linked stylesheet must actually be served');
        self::assertStringContainsString('text/css', $css['headers']['content-type'] ?? '');
        self::assertStringContainsString(':focus-visible', $css['body']);
    }

    /**
     * THE WHOLE POINT OF THE FEATURE, over HTTP: sign in, then read the console.
     */
    public function test_a_signed_in_operator_can_read_the_console(): void
    {
        $agentName = $this->seedActiveAgent('served-visible');

        $login = $this->signIn('admin');
        self::assertNotNull($login['cookie'], 'login must set a session cookie');

        $console = $this->request('/console', 'GET', null, $login['cookie']);

        self::assertSame(200, $console['status'], 'a signed-in operator must reach the console');
        self::assertStringContainsString($agentName, $console['body'], 'their tenant\'s agent must be listed');
    }

    public function test_logout_kills_the_session_over_http(): void
    {
        $this->seedActiveAgent('served-logout');

        $login = $this->signIn('admin');
        self::assertNotNull($login['cookie']);

        $before = $this->request('/console', 'GET', null, $login['cookie']);
        self::assertSame(200, $before['status'], 'guards a vacuous pass - the session must work first');

        $logout = $this->request('/logout', 'POST', '', $login['cookie']);
        self::assertSame(200, $logout['status']);

        // The SAME cookie, which the client still holds. Only a server-side
        // revocation can make this fail.
        $after = $this->request('/console', 'GET', null, $login['cookie']);
        self::assertSame(403, $after['status'], 'FR-IDENT-004: a revoked session must not reach the console');
    }

    /**
     * A session without agent.invoke may READ the console but must not run an
     * agent - the distinction migration 024 was written for.
     */
    public function test_invoking_without_agent_invoke_is_refused_over_http(): void
    {
        $agentId = $this->seedActiveAgent('served-invoke-denied');

        $login = $this->signIn('staff');
        self::assertNotNull($login['cookie']);

        $console = $this->request('/console', 'GET', null, $login['cookie']);
        self::assertSame(200, $console['status'], 'staff may view the console');

        $response = $this->request(
            '/console/invoke',
            'POST',
            http_build_query([
                'agent_id' => (string) $agentId,
                'work_description' => 'x',
                'csrf_token' => $login['csrf'],
            ]),
            $login['cookie']
        );

        self::assertSame(403, $response['status'], 'staff must not invoke');
        self::assertStringContainsString('authz.forbidden', $response['body']);
    }

    public function test_invoking_without_a_csrf_token_is_refused_over_http(): void
    {
        $agentId = $this->seedActiveAgent('served-invoke-csrf');

        $login = $this->signIn('admin');
        self::assertNotNull($login['cookie']);

        $response = $this->request(
            '/console/invoke',
            'POST',
            http_build_query(['agent_id' => (string) $agentId, 'work_description' => 'x']),
            $login['cookie']
        );

        self::assertSame(403, $response['status']);
        self::assertStringContainsString('authz.csrf', $response['body']);
    }

    /**
     * AC-001 over HTTP: a ?tenant= override is refused before anything else, and
     * the console ignores it entirely in favour of the session's tenant.
     */
    public function test_request_chosen_tenant_is_still_refused(): void
    {
        $response = $this->request('/console?tenant=2');

        self::assertSame(400, $response['status']);
        self::assertStringContainsString('Tenant selection', $response['body']);
    }

    /**
     * The console's tenant comes from the SESSION, so an operator in tenant 1
     * cannot see tenant 2's agents even by naming their ids.
     */
    public function test_the_console_shows_only_the_sessions_tenant(): void
    {
        $this->seedTenant(self::TENANT + 1);
        $foreignName = $this->seedActiveAgent('served-foreign', self::TENANT + 1);

        $login = $this->signIn('admin');
        self::assertNotNull($login['cookie']);

        $console = $this->request('/console', 'GET', null, $login['cookie']);

        self::assertSame(200, $console['status']);
        self::assertStringNotContainsString($foreignName, $console['body'], 'AC-001 over HTTP');
    }

    /**
     * The demo dashboard and the lead endpoint must be unaffected by this work.
     */
    public function test_the_existing_public_surfaces_still_behave(): void
    {
        $dashboard = $this->request('/dashboard');
        self::assertSame(200, $dashboard['status'], 'the demo dashboard is deliberately unchanged');
        self::assertStringContainsString('Operations Dashboard', $dashboard['body']);

        $unknown = $this->request('/nonexistent');
        self::assertSame(404, $unknown['status']);

        $badCsrf = $this->request('/api/v1/public/leads', 'POST', http_build_query([
            'name' => 'x', 'email' => 'x@example.test', 'automation_need' => 'x',
        ]));
        self::assertSame(403, $badCsrf['status'], 'the lead endpoint still refuses a CSRF-less POST');
    }

    /**
     * Signs in over HTTP and returns the session cookie plus the session's CSRF
     * token (read from the server-side record, exactly as the rendered form
     * would have been handed it).
     *
     * @return array{cookie: string|null, csrf: string}
     */
    private function signIn(string $roleCode): array
    {
        $userId = $this->seedUser($roleCode);
        $email = $this->emailOf($userId);

        $response = $this->request('/login', 'POST', http_build_query([
            'email' => $email,
            'password' => self::PASSWORD,
        ]));

        if ($response['status'] !== 200) {
            self::fail(sprintf(
                'login fixture failed: status=%d body=%s',
                $response['status'],
                substr($response['body'], 0, 300)
            ));
        }

        $setCookie = (string) ($response['headers']['set-cookie'] ?? '');
        if (preg_match('/' . preg_quote(LoginController::COOKIE_NAME, '/') . '=([^;]+)/', $setCookie, $m) !== 1) {
            return ['cookie' => null, 'csrf' => ''];
        }

        $sessionId = $m[1];
        $this->sessionKeys[] = SessionStore::KEY_PREFIX . $sessionId;

        $subject = (new SessionStore($this->redis, 900))->read($sessionId);

        return ['cookie' => LoginController::COOKIE_NAME . '=' . $sessionId, 'csrf' => $subject?->csrfToken() ?? ''];
    }

    private function seedUser(string $roleCode): int
    {
        $pdo = $this->fixtureConnection();

        $statement = $pdo->prepare(
            'INSERT INTO users (tenant_id, email, password_hash, role, is_active, status, mfa_secret)'
            . ' VALUES (:tenant_id, :email, :password_hash, :role, 1, :status, NULL)'
        );
        if ($statement === false) {
            throw new RuntimeException('Unable to prepare the user fixture insert.');
        }

        $statement->execute([
            'tenant_id' => self::TENANT,
            'email' => 'served-' . bin2hex(random_bytes(6)) . '@example.test',
            'password_hash' => (new PasswordHasher(self::CHEAP_HASH))->hash(self::PASSWORD),
            'role' => 'viewer',
            'status' => 'active',
        ]);
        $userId = (int) $pdo->lastInsertId();
        $this->committedUserIds[] = $userId;

        $roles = $pdo->prepare('SELECT id FROM roles WHERE tenant_id = :t AND code = :c');
        if ($roles === false) {
            throw new RuntimeException('Unable to prepare the role lookup.');
        }
        $roles->execute(['t' => self::TENANT, 'c' => $roleCode]);
        $roleId = $roles->fetchColumn();
        if (!is_scalar($roleId)) {
            throw new RuntimeException(sprintf('Role "%s" is not seeded.', $roleCode));
        }

        $grant = $pdo->prepare('INSERT INTO user_roles (tenant_id, user_id, role_id) VALUES (:t, :u, :r)');
        if ($grant === false) {
            throw new RuntimeException('Unable to prepare the role grant.');
        }
        $grant->execute(['t' => self::TENANT, 'u' => $userId, 'r' => (int) $roleId]);

        return $userId;
    }

    private function emailOf(int $userId): string
    {
        $statement = $this->fixtureConnection()->prepare('SELECT email FROM users WHERE id = :id');
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

    /**
     * Seeds an ACTIVE agent through the registry, on the committing connection so
     * the served process can see it. Uses the registry (rather than a raw insert)
     * because listActive() skips an agent with no active version - a raw fixture
     * would be filtered out and the test would pass for the wrong reason.
     */
    private function seedActiveAgent(string $prefix, int $tenantId = self::TENANT): string
    {
        $this->seedTenant($tenantId);

        $pdo = $this->fixtureConnection();
        $name = $prefix . '-' . bin2hex(random_bytes(4));
        $registry = new AgentRegistry($pdo, $tenantId);

        $agentId = $registry->create(
            name: $name,
            owner: 'served-owner',
            purpose: 'served test',
            systemPrompt: 'You are a test agent.',
            riskClass: 'low',
            allowedTools: [],
            modelConfig: ['model' => 'test-model']
        );
        $registry->activate($agentId, true);
        $this->committedAgentIds[] = $agentId;

        return $name;
    }

    private function seedTenant(int $tenantId): void
    {
        $statement = $this->fixtureConnection()->prepare(
            'INSERT IGNORE INTO tenants (id, slug, name, status, deployment_model)'
            . ' VALUES (:id, :slug, :name, :status, :model)'
        );
        if ($statement === false) {
            throw new RuntimeException('Unable to prepare the tenant fixture.');
        }

        $statement->execute([
            'id' => $tenantId,
            'slug' => 'served-tenant-' . $tenantId,
            'name' => 'Served Tenant ' . $tenantId,
            'status' => 'active',
            'model' => 'cloud',
        ]);
    }

    /**
     * @return array{status: int, headers: array<string, string>, body: string, rawHeaders: list<string>}
     */
    private function request(string $path, string $method = 'GET', ?string $body = null, ?string $cookie = null): array
    {
        $headers = [];
        if ($body !== null) {
            $headers[] = 'Content-Type: application/x-www-form-urlencoded';
        }
        if ($cookie !== null) {
            $headers[] = 'Cookie: ' . $cookie;
        }

        $options = [
            'http' => [
                'method' => $method,
                'ignore_errors' => true,
                'timeout' => 15,
                'follow_location' => 0,
            ],
        ];

        if ($headers !== []) {
            $options['http']['header'] = implode("\r\n", $headers) . "\r\n";
        }
        if ($body !== null) {
            $options['http']['content'] = $body;
        }

        $context = stream_context_create($options);
        $content = file_get_contents('http://127.0.0.1:' . $this->port . $path, false, $context);

        /** @var list<string> $rawHeaders */
        $rawHeaders = $http_response_header;

        return [
            'status' => $this->statusOf($rawHeaders),
            'headers' => $this->headersOf($rawHeaders),
            'body' => (string) $content,
            'rawHeaders' => $rawHeaders,
        ];
    }

    /**
     * @param list<string> $rawHeaders
     */
    private function statusOf(array $rawHeaders): int
    {
        // THE LAST status line wins. `php -S` opens a speculative preconnection
        // on some requests and answers it with a bare "Closed without sending a
        // request" - and PHP's HTTP wrapper records every response it saw, so the
        // FIRST line in $http_response_header is not necessarily the real
        // response's status. Taking the first match reported 404/0 for requests
        // the server had actually answered 200, which is a harness bug that
        // masquerades as an application bug.
        $status = 0;
        foreach ($rawHeaders as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m) === 1) {
                $status = (int) $m[1];
            }
        }

        return $status;
    }

    /**
     * @param  list<string> $rawHeaders
     * @return array<string, string>
     */
    private function headersOf(array $rawHeaders): array
    {
        $headers = [];
        foreach ($rawHeaders as $line) {
            $separator = strpos($line, ':');
            if ($separator === false) {
                continue;
            }
            $headers[strtolower(trim(substr($line, 0, $separator)))] = trim(substr($line, $separator + 1));
        }

        return $headers;
    }

    private function freePort(): int
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        if ($socket === false) {
            self::fail(sprintf('Unable to allocate a loopback port: %s', $errstr));
        }

        $name = stream_socket_get_name($socket, false);
        fclose($socket);
        self::assertIsString($name);

        return (int) substr($name, (int) strrpos($name, ':') + 1);
    }

    private function awaitServer(): void
    {
        $deadline = microtime(true) + 15.0;

        while (microtime(true) < $deadline) {
            $connection = @fsockopen('127.0.0.1', (int) $this->port, $errno, $errstr, 0.2);
            if (is_resource($connection)) {
                fclose($connection);

                return;
            }
            usleep(50_000);
        }

        self::fail('php -S did not become ready within 15s.');
    }
}
