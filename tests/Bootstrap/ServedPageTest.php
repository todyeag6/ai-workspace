<?php

declare(strict_types=1);

namespace App\Tests\Bootstrap;

use App\Bootstrap\SecurityHeaders;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * SEC-004 / SEC-009 (BR-12.5) - the SERVED surface.
 *
 * WHY THIS EXISTS. Every other test in the suite exercises a controller as a
 * pure array-in/array-out function, so nothing proved that public/index.php
 * actually wires them up or emits the security headers on the responses a real
 * client sees. The external pen-test (SEC-009) found exactly that class of gap:
 * headers missing on early-exit error paths, and a form whose action was never
 * routed. This test drives the real front controller over HTTP.
 *
 * HOW. PHP's built-in server (`php -S`) runs the same public/index.php the
 * production SAPI runs, on a free loopback port, with its own process env. No
 * framework, no extra dependency: the server is part of the PHP runtime, so
 * this runs identically in CI and in the container.
 *
 * The server is pointed at the TEST database (TEST_DB_DSN), never the dev
 * database, so a served POST cannot write into a developer's working data.
 *
 * © AI WebScapes 2026
 */
final class ServedPageTest extends TestCase
{
    private const DOCROOT = '/app/public';

    private ?int $port = null;

    /** @var resource|null */
    private $server = null;

    /** @var array<int, resource> */
    private array $pipes = [];

    protected function setUp(): void
    {
        $this->port = $this->freePort();

        // getenv() with no arguments returns the whole environment, so PATH and
        // friends survive; only the keys we must override are replaced. Passing
        // an env array to proc_open REPLACES the environment outright, which is
        // why it is seeded from the current one rather than built from scratch.
        $env = getenv();
        $env['DB_DSN'] = (string) (getenv('TEST_DB_DSN') ?: '');
        $env['REDIS_DSN'] = (string) (getenv('REDIS_DSN') ?: 'tcp://redis:6379');
        $env['APP_TENANT_ID'] = '1';
        // The public lead endpoint derives its throttle identity from an HMAC
        // keyed by APP_KEY. In production that key is mandatory; here it is a
        // fixed test value so the served POST is deterministic.
        $env['APP_KEY'] = 'served-page-test-ip-hash-secret';

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

        self::assertIsResource($server, 'php -S must start.');
        $this->server = $server;

        $this->awaitServer();
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
    }

    /**
     * D2 / SEC-004: the dashboard stylesheet is a real, separately-served asset.
     *
     * The page used to carry an inline <style> block, which forced the CSP to
     * grant style-src 'unsafe-inline' - the weakest possible style policy, and
     * the one the pen-test flagged. A linked stylesheet lets the policy drop to
     * style-src 'self' with no loss of styling.
     */
    #[Test]
    public function test_dashboard_stylesheet_is_served_and_linked(): void
    {
        $page = $this->request('/dashboard');

        self::assertSame(200, $page['status']);
        self::assertStringContainsString(
            '<link rel="stylesheet" href="/assets/dashboard.css">',
            $page['body'],
            'The dashboard must link its stylesheet rather than inlining it.'
        );
        self::assertStringNotContainsString(
            '<style',
            $page['body'],
            'No inline <style> block may remain: it is what forces unsafe-inline.'
        );

        $css = $this->request('/assets/dashboard.css');

        self::assertSame(200, $css['status'], 'The linked stylesheet must actually be served.');
        self::assertStringContainsString('text/css', $css['headers']['content-type'] ?? '');
        self::assertStringContainsString(':focus-visible', $css['body'], 'A11Y-002 focus styling must survive the move.');
    }

    /**
     * SEC-009: every response carries the security headers, including the
     * early-exit error paths. These branches return before the page is built, so
     * they used to go out bare - no CSP, no nosniff - which the pen-test flagged
     * as "CSP Header Not Set" and "X-Content-Type-Options Missing".
     */
    #[Test]
    public function test_security_headers_present_on_early_exit_error_paths(): void
    {
        $page = $this->request('/dashboard?tenant=2');

        self::assertSame(400, $page['status'], 'A request-chosen tenant must still be refused.');
        self::assertSame(
            SecurityHeaders::all()['Content-Security-Policy'],
            $page['headers']['content-security-policy'] ?? null,
            'The 400 path must carry the CSP.'
        );
        self::assertSame('nosniff', $page['headers']['x-content-type-options'] ?? null);
        self::assertSame('DENY', $page['headers']['x-frame-options'] ?? null);
        self::assertSame('no-referrer', $page['headers']['referrer-policy'] ?? null);
    }

    /**
     * SEC-009: PHP must not advertise its own version. expose_php (INI_SYSTEM,
     * php.ini only) defaults to On and stamps "X-Powered-By: PHP/8.3.33" on every
     * response, which hands an attacker the exact version to match exploits
     * against. Baked off in the image; see the Dockerfile.
     */
    #[Test]
    public function test_php_version_is_not_advertised(): void
    {
        $page = $this->request('/dashboard');

        self::assertArrayNotHasKey(
            'x-powered-by',
            $page['headers'],
            'X-Powered-By leaks the PHP version (expose_php must be Off).'
        );
    }

    /**
     * LFR-AI-002 / FR-DASH-001: the public lead-capture endpoint accepts a valid
     * POST and returns 202 with a correlation ID. Proves the full HTTP path:
     * CSRF cookie minted by the dashboard GET -> cookie sent back on POST ->
     * LeadController validates and LeadService persists the lead.
     */
    #[Test]
    public function test_lead_capture_post_returns_202_on_valid_submission(): void
    {
        // Step 1: GET the dashboard to mint a CSRF cookie.
        $dashboard = $this->request('/dashboard');
        self::assertSame(200, $dashboard['status']);

        // Extract the csrf_token cookie from the response headers.
        $csrfCookie = $this->extractCookie($dashboard['headers']['set-cookie'] ?? '', 'csrf_token');
        self::assertNotNull($csrfCookie, 'The dashboard must set a csrf_token cookie.');

        // Step 2: POST the lead with the CSRF cookie + token.
        $body = http_build_query([
            'name' => 'Test Lead',
            'email' => 'test@example.com',
            'automation_need' => 'Test need',
            'csrf_token' => $csrfCookie,
        ]);

        $response = $this->request('/api/v1/public/leads', 'POST', $body, ['csrf_token' => $csrfCookie]);

        self::assertSame(202, $response['status'], 'A valid lead POST must return 202.');
        self::assertStringContainsString('correlation_id', $response['body']);
    }

    /**
     * SEC-010 / CSRF: a POST without a matching CSRF cookie + token is refused
     * with 403. This is the security validation that prevents cross-site request
     * forgery on the public lead endpoint.
     */
    #[Test]
    public function test_lead_capture_post_refused_without_csrf(): void
    {
        $body = http_build_query([
            'name' => 'Test Lead',
            'email' => 'test@example.com',
            'automation_need' => 'Test need',
        ]);

        $response = $this->request('/api/v1/public/leads', 'POST', $body);

        self::assertSame(403, $response['status'], 'A POST without CSRF must be refused.');
        self::assertStringContainsString('Security validation failed', $response['body']);
    }

    /**
     * FR-DASH-001 / A11Y-003: the lead form returns 422 with field-level errors
     * when required fields are missing. The error keys must match the form field
     * names so the frontend can highlight the correct fields.
     */
    #[Test]
    public function test_lead_capture_post_returns_422_on_missing_fields(): void
    {
        $dashboard = $this->request('/dashboard');
        self::assertSame(200, $dashboard['status']);
        $csrfCookie = $this->extractCookie($dashboard['headers']['set-cookie'] ?? '', 'csrf_token');
        self::assertNotNull($csrfCookie);

        // Missing 'name' field.
        $body = http_build_query([
            'email' => 'test@example.com',
            'automation_need' => 'Test need',
            'csrf_token' => $csrfCookie,
        ]);

        $response = $this->request('/api/v1/public/leads', 'POST', $body, ['csrf_token' => $csrfCookie]);

        self::assertSame(422, $response['status'], 'A missing required field must return 422.');
        self::assertStringContainsString('name', $response['body']);
    }

    /**
     * FR-CONF-002: when the database is unavailable, the front controller returns
     * 500 with a generic error message (no stack trace, no DB credentials). This
     * is the fail-closed posture: the app refuses to serve rather than leak
     * internals.
     */
    #[Test]
    public function test_dashboard_returns_500_when_db_unavailable(): void
    {
        // Start a second server with a bad DSN.
        $port = $this->freePort();
        $env = getenv();
        $env['DB_DSN'] = 'mysql:host=nonexistent;dbname=aiwebscapes;charset=utf8mb4';
        $env['APP_TENANT_ID'] = '1';
        $env['APP_KEY'] = 'served-page-test-ip-hash-secret';

        $command = [PHP_BINARY, '-S', '127.0.0.1:' . $port, '-t', self::DOCROOT, self::DOCROOT . '/index.php'];
        $server = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, self::DOCROOT, $env);
        self::assertIsResource($server);

        try {
            $this->awaitServerOnPort($port);
            $response = $this->requestOnPort($port, '/dashboard');
            self::assertSame(500, $response['status'], 'DB-down must return 500.');
            self::assertStringContainsString('Database unavailable', $response['body']);
        } finally {
            proc_terminate($server);
            proc_close($server);
            foreach ($pipes as $pipe) {
                if (is_resource($pipe)) {
                    fclose($pipe);
                }
            }
        }
    }

    /**
     * A 404 for an unknown route. The front controller must return a clean 404
     * for any path that is not /dashboard or /api/v1/public/leads.
     */
    #[Test]
    public function test_unknown_route_returns_404(): void
    {
        $response = $this->request('/nonexistent');
        self::assertSame(404, $response['status']);
        self::assertStringContainsString('Not found', $response['body']);
    }

    /**
     * Extract a cookie value from a Set-Cookie header string.
     */
    private function extractCookie(string $setCookieHeader, string $cookieName): ?string
    {
        if (preg_match('/(?:^|;\s*)' . preg_quote($cookieName, '/') . '=([^;]+)/', $setCookieHeader, $matches) === 1) {
            return $matches[1];
        }
        return null;
    }

    /**
     * Poll a specific port until the server is ready.
     */
    private function awaitServerOnPort(int $port): void
    {
        $deadline = microtime(true) + 10.0;
        while (microtime(true) < $deadline) {
            $connection = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.2);
            if (is_resource($connection)) {
                fclose($connection);
                return;
            }
            usleep(50_000);
        }
        self::fail('php -S did not become ready on port ' . $port . ' within 10s.');
    }

    /**
     * Make a request to a specific port.
     *
     * @param array<string, string> $cookies Cookie name => value to send.
     * @return array{status: int, headers: array<string, string>, body: string}
     */
    private function requestOnPort(int $port, string $path, string $method = 'GET', ?string $body = null, array $cookies = []): array
    {
        $headers = [];
        if ($body !== null) {
            $headers[] = "Content-Type: application/x-www-form-urlencoded";
        }
        if ($cookies !== []) {
            $cookiePairs = [];
            foreach ($cookies as $name => $value) {
                $cookiePairs[] = $name . '=' . $value;
            }
            $headers[] = "Cookie: " . implode('; ', $cookiePairs);
        }

        $options = [
            'http' => [
                'method' => $method,
                'ignore_errors' => true,
                'timeout' => 10,
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
        $content = file_get_contents('http://127.0.0.1:' . $port . $path, false, $context);

        /** @var list<string> $rawHeaders */
        $rawHeaders = $http_response_header;

        return [
            'status' => $this->statusOf($rawHeaders),
            'headers' => $this->headersOf($rawHeaders),
            'body' => (string) $content,
        ];
    }

    /**
     * A free loopback port for the test server. Binding port 0 lets the OS pick
     * one; the socket is closed immediately and the port handed to php -S.
     */
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

    /**
     * Polls until the server accepts a connection, so a request never races the
     * process start. Bounded, so a server that dies on boot fails fast instead
     * of hanging the suite.
     */
    private function awaitServer(): void
    {
        $deadline = microtime(true) + 10.0;

        while (microtime(true) < $deadline) {
            $connection = @fsockopen('127.0.0.1', (int) $this->port, $errno, $errstr, 0.2);
            if (is_resource($connection)) {
                fclose($connection);

                return;
            }

            usleep(50_000);
        }

        self::fail('php -S did not become ready within 10s.');
    }

    /**
     * @param array<string, string> $cookies Cookie name => value to send.
     * @return array{status: int, headers: array<string, string>, body: string}
     */
    private function request(string $path, string $method = 'GET', ?string $body = null, array $cookies = []): array
    {
        $headers = [];
        if ($body !== null) {
            $headers[] = "Content-Type: application/x-www-form-urlencoded";
        }
        if ($cookies !== []) {
            $cookiePairs = [];
            foreach ($cookies as $name => $value) {
                $cookiePairs[] = $name . '=' . $value;
            }
            $headers[] = "Cookie: " . implode('; ', $cookiePairs);
        }

        $options = [
            'http' => [
                'method' => $method,
                'ignore_errors' => true,
                'timeout' => 10,
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
        ];
    }

    /**
     * @param list<string> $rawHeaders
     */
    private function statusOf(array $rawHeaders): int
    {
        foreach ($rawHeaders as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $matches) === 1) {
                return (int) $matches[1];
            }
        }

        return 0;
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

            $name = strtolower(trim(substr($line, 0, $separator)));
            $headers[$name] = trim(substr($line, $separator + 1));
        }

        return $headers;
    }
}
