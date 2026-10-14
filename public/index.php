<?php

/**
 * The front controller: the platform's single HTTP entrypoint.
 *
 * SHAPE. Deliberately tiny and framework-free, consistent with the as-built
 * decision in docs/adr/0001-modular-monolith.md and the P1-T15 deviation
 * (docs/SESSION_HANDOFF_P1T14.md): every controller is array-in/array-out and
 * tested directly, so this file's only jobs are to route, emit headers, and
 * translate a controller's array response into HTTP. Standing up a Slim kernel
 * for a handful of routes would add unbuilt scope and a fresh attack surface
 * for no functional gain.
 *
 * WHAT IS PUBLIC AND WHAT IS NOT.
 *   GET  /login                  public  - the sign-in form
 *   POST /login                  public  - authenticate
 *   POST /logout                 public  - revoke (needs no session; idempotent)
 *   GET  /console                GATED   - requires agent.console.view
 *   POST /console/invoke         GATED   - requires agent.invoke + CSRF + object check
 *   POST /api/v1/public/leads    public  - lead capture (behaviour unchanged)
 *   GET  /dashboard              unchanged demo surface (see the NOTE below)
 *
 * EVERYTHING GATED GOES THROUGH TenantAuthMiddleware, and the gate runs BEFORE
 * the controller is constructed. That ordering is the point: an unauthorised
 * request never reaches code that reads tenant data, so no controller can be
 * asked to render for a caller who may not see it.
 *
 * NOTE ON /dashboard - A DELIBERATE NON-CHANGE. The demo dashboard predates this
 * work, is not wired into any auth flow by its own admission, and is asserted
 * UNAUTHENTICATED by tests/Bootstrap/ServedPageTest.php. Gating it would be
 * scope expansion beyond "make the agents reachable" AND would break shipped
 * tests. It is left exactly as it was. That it serves lead-pipeline counts
 * without a session is a REAL finding, recorded rather than silently changed -
 * see the ADR (T12). Anyone deploying this beyond localhost must decide that
 * surface's fate deliberately.
 *
 * SECURITY (AC-001 / SEC-009 / SEC-010).
 *  - Security headers are emitted FIRST, before every branch, so the 400, 403,
 *    405, 500, 404 and 200 paths all carry the identical policy. The pen-test
 *    found them missing on early-exit paths; this ordering is that fix and must
 *    not be disturbed.
 *  - Tenant identity is server-fixed (APP_TENANT_ID) for the public surfaces and
 *    comes from the SERVER-SIDE SESSION for the console (AC-001). A ?tenant=
 *    override is refused outright.
 *  - The console's tenant is read from the session record, which only the server
 *    can write - never from the request.
 *  - The session id is read from the COOKIE ONLY, never a query parameter or
 *    header (NIST SP 800-63B-4 §5.1.1; OWASP Session Management Cheat Sheet).
 *
 * © AI WebScapes 2026
 */

declare(strict_types=1);

use App\Agents\AgentRegistry;
use App\Agents\AgentResourceLocator;
use App\AI\AIGateway;
use App\AI\LocalAdapter;
use App\AI\SchemaValidator;
use App\Audit\AuditLog;
use App\Bootstrap\SecurityHeaders;
use App\Console\AgentConsoleController;
use App\Console\AgentConsoleView;
use App\Console\AgentInvocationController;
use App\Dashboard\DashboardController;
use App\Data\PasswordResetTokenRepository;
use App\Data\UserRepository;
use App\Identity\AuthService;
use App\Identity\LoginController;
use App\Identity\PasswordHasher;
use App\Identity\SessionStore;
use App\Leads\CsrfCookie;
use App\Leads\LeadController;
use App\Leads\LeadService;
use App\Manager\ManagerOrchestrator;
use App\Manager\ManagerReviewRepository;
use App\Manager\ManagerTaskRepository;
use App\Security\CsrfGuard;
use App\Security\RateLimiter;
use App\Security\RbacPolicy;
use App\Security\TenantAuthMiddleware;

require __DIR__ . '/../vendor/autoload.php';

// SECURITY HEADERS FIRST. Emitted before any branch so every response - the
// tenant-override 400, the DB-down 500, the 404 tail and the 200 page - carries
// the identical policy. Previously they were applied only on the success/404
// tail, so the early-exit error paths returned with no CSP and no nosniff
// (SEC-009). Applying here also keeps the static passthrough above it untouched:
// a served asset returns before this line, exactly as Apache/nginx would.
SecurityHeaders::apply();

// STATIC PASSTHROUGH. In production the web server (Apache/nginx) serves files
// under public/ directly and PHP never sees them. PHP's built-in dev server has
// no such rule when a router script is supplied - every request reaches this
// file - so hand an existing static file (the dashboard stylesheet) back to the
// server with `return false`. Guarded on the SAPI so it is inert anywhere else.
$requestedPath = parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?: '/';
if (PHP_SAPI === 'cli-server' && $requestedPath !== '/' && is_file(__DIR__ . $requestedPath)) {
    return false;
}

$dsn = getenv('DB_DSN');
if ($dsn === false || $dsn === '') {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "DB_DSN is not configured.\n";
    exit;
}

// Tenant identity is server-fixed, never request-derived (AC-001).
$tenantId = (int) (getenv('APP_TENANT_ID') ?: '1');
if ($tenantId <= 0) {
    $tenantId = 1;
}

// Refuse any attempt to choose the tenant from the request.
foreach (['tenant', 'tid', 'tenant_id'] as $forbidden) {
    if (isset($_GET[$forbidden])) {
        http_response_code(400);
        header('Content-Type: text/plain; charset=utf-8');
        echo "Tenant selection from the request is not permitted.\n";
        exit;
    }
}

$path = parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?: '/';
$method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));

try {
    $pdo = new PDO($dsn, 'root', 'root', [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
} catch (Throwable $e) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Database unavailable.\n";
    exit;
}

/**
 * Renders a controller's array response as HTTP and terminates.
 *
 * @param array{status: int, body: array<string, mixed>, headers?: array<string, string>} $response
 */
$emit = static function (array $response, bool $json = false): void {
    http_response_code($response['status']);

    foreach ($response['headers'] ?? [] as $name => $value) {
        header($name . ': ' . $value);
    }

    if ($json) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($response['body']);
    } else {
        header('Content-Type: text/html; charset=utf-8');

        if ($response['status'] === 200) {
            echo (string) ($response['body']['html'] ?? '');
        } else {
            // The refusal reason is included, not hidden. It tells the operator
            // what to DO (sign in / re-fetch the form / ask for the permission)
            // and reveals nothing an unauthorised caller could act on - they
            // already know they were refused. The single "object_unavailable"
            // reason for both "wrong id" and "someone else's id" is what keeps
            // the id space unenumerable (AC-001).
            $reason = is_scalar($response['body']['reason'] ?? null) ? (string) $response['body']['reason'] : '';
            echo htmlspecialchars((string) ($response['body']['message'] ?? 'Error.'), ENT_QUOTES | ENT_HTML5, 'UTF-8');
            if ($reason !== '') {
                echo "\n" . htmlspecialchars($reason, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            }
        }
    }

    // MUST be exit, not return. `return` inside a closure returns from the
    // CLOSURE, not from the script - so the router would carry on past $emit(),
    // fall through to the dashboard route and overwrite the response. That is
    // exactly what happened: a successful login emitted its 200 and its session
    // cookie, then fell through and was replaced by the dashboard's 404 (and a
    // second csrf_token cookie). The client saw 404 while the login branch had
    // genuinely succeeded, which reads as a broken login rather than a control
    // flow bug.
    exit;
};

/**
 * A Redis client. Host and port come from the environment so the same file works
 * in the compose stack (`redis:6379`), on a CI runner (127.0.0.1) and on a host -
 * a hardcoded hostname is what made the CI suite fail before.
 */
$redis = static function (): Predis\Client {
    return new Predis\Client([
        'scheme' => 'tcp',
        'host' => getenv('REDIS_HOST') ?: 'redis',
        'port' => (int) (getenv('REDIS_PORT') ?: 6379),
    ]);
};

$isSecureRequest = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (int) ($_SERVER['SERVER_PORT'] ?? 0) === 443;

// The session id, from the COOKIE ONLY. Never a query parameter or a header:
// limiting the exchange mechanism to cookies is required by NIST SP 800-63B-4
// §5.1.1 and the OWASP Session Management Cheat Sheet, and accepting an id from
// the URL would let a link carry someone else's session.
$sessionId = is_scalar($_COOKIE[LoginController::COOKIE_NAME] ?? null)
    ? (string) $_COOKIE[LoginController::COOKIE_NAME]
    : '';

$cookies = is_array($_COOKIE) ? $_COOKIE : [];
$body = is_array($_POST) ? $_POST : [];
$view = new AgentConsoleView();

// ---------------------------------------------------------------------------
// PUBLIC: login and logout
// ---------------------------------------------------------------------------
if ($path === LoginController::PATH || $path === LoginController::LOGOUT_PATH) {
    $sessions = new SessionStore($redis(), 900);
    $auth = new AuthService(
        new UserRepository($pdo, $tenantId),
        new PasswordResetTokenRepository($pdo, $tenantId),
        new PasswordHasher(),
        $sessions,
        new AuditLog($pdo)
    );

    $loginController = new LoginController($auth, $sessions, $isSecureRequest);
    $response = $loginController->handle([
        'method' => $method,
        'path' => $path,
        'body' => $body,
        'cookies' => $cookies,
    ]);

    // A successful GET is a request to RENDER the form. The controller returns a
    // marker rather than markup, so the view remains the only thing that knows
    // HTML and the accessibility guarantees stay testable without a database.
    if (($response['body']['render'] ?? null) === 'login') {
        $emit(['status' => 200, 'body' => ['html' => $view->renderLogin()]]);
    }

    $emit($response, $path === LoginController::LOGOUT_PATH);
}

// ---------------------------------------------------------------------------
// GATED: the agent console
// ---------------------------------------------------------------------------
if ($path === AgentConsoleController::PATH || $path === AgentInvocationController::PATH) {
    $middleware = new TenantAuthMiddleware(
        new SessionStore($redis(), 900),
        new RbacPolicy($pdo),
        new AuditLog($pdo),
        new AgentResourceLocator($pdo),
        new CsrfGuard()
    );

    $requestedAgentId = is_scalar($body['agent_id'] ?? null) ? (string) $body['agent_id'] : null;
    $isInvocation = $path === AgentInvocationController::PATH;

    $authorisation = $middleware->authorise(
        $sessionId === '' ? null : $sessionId,
        $isInvocation
            ? AgentInvocationController::REQUIRED_PERMISSION
            : AgentConsoleController::REQUIRED_PERMISSION,
        $isInvocation ? $requestedAgentId : null,
        $method,
        is_scalar($body['csrf_token'] ?? null) ? (string) $body['csrf_token'] : null
    );

    if (!$authorisation->allowed()) {
        // 403 for EVERY refusal, including "no session". A 401 here would tell an
        // unauthenticated caller that the route exists and is merely missing
        // credentials - a small, free piece of reconnaissance.
        $emit(['status' => 403, 'body' => [
            'message' => 'You are not permitted to view this page.',
            'reason' => $authorisation->reason(),
        ]]);
    }

    $subject = $authorisation->subject();
    $sessionTenantId = $subject?->tenantId() ?? $tenantId;

    if (!$isInvocation) {
        $controller = new AgentConsoleController(
            new AgentRegistry($pdo, $sessionTenantId),
            $view,
            'staff',
            // The session's own CSRF token, so the rendered invoke form carries a
            // token the middleware will accept. This is why the console needs no
            // JavaScript: the token is available server-side at render time.
            $subject?->csrfToken() ?? ''
        );
        $emit($controller->handle(['method' => $method, 'path' => $path]));
    }

    $orchestrator = new ManagerOrchestrator(
        new AgentRegistry($pdo, $sessionTenantId),
        // LocalAdapter requires the base URL explicitly and fails closed when it
        // is absent (FR-CONF-002) rather than defaulting to localhost - so the
        // DSN comes from the environment, matching compose.yaml.
        new AIGateway(
            new LocalAdapter((string) (getenv('AI_LOCAL_BASE_URL') ?: 'http://host.docker.internal:11434/v1')),
            new SchemaValidator()
        ),
        (string) (getenv('AI_MODEL') ?: 'hermes3:8b'),
        new ManagerTaskRepository($pdo, $sessionTenantId),
        new ManagerReviewRepository($pdo, $sessionTenantId)
    );

    $invocation = new AgentInvocationController(
        $middleware,
        new AgentRegistry($pdo, $sessionTenantId),
        $orchestrator,
        new AuditLog($pdo)
    );
    $emit($invocation->handle([
        'method' => $method,
        'path' => $path,
        'body' => $body,
        'cookies' => $cookies,
    ]), true);
}

// ---------------------------------------------------------------------------
// PUBLIC: lead capture (behaviour unchanged)
// ---------------------------------------------------------------------------
if ($path === '/api/v1/public/leads' && $method === 'POST') {
    $service = new LeadService(
        $pdo,
        new RateLimiter($redis(), 'pub:leads:' . $tenantId, 100, 60),
        null
    );

    $leadController = new LeadController(
        $service,
        (string) $tenantId,
        getenv('APP_KEY') ?: 'dev-ip-hash-secret',
        null,
        null,
        // Verify against the cookie the browser sent, not a freshly minted one.
        is_scalar($_COOKIE[CsrfCookie::COOKIE_NAME] ?? null)
            ? (string) $_COOKIE[CsrfCookie::COOKIE_NAME]
            : ''
    );

    $response = $leadController->handle([
        'method' => $method,
        'path' => $path,
        'body' => $body,
        'server' => $_SERVER,
    ]);

    http_response_code($response['status']);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($response['body']);
    exit;
}

// DOUBLE-SUBMIT CSRF COOKIE. Issued whenever absent so the dashboard GET that
// renders the lead form has the cookie set before the browser reads it (the
// form's hidden field is populated from document.cookie). The lead POST branch
// above only ever *verifies* the existing cookie - it never mints a new one, or
// the first submission would always fail. OWASP CSRF Cheat Sheet § 3.2.
if (!isset($_COOKIE[CsrfCookie::COOKIE_NAME])) {
    $csrfFlags = CsrfCookie::cookieFlags();
    setcookie(
        CsrfCookie::COOKIE_NAME,
        CsrfCookie::generateToken(),
        [
            'expires' => time() + 3600,
            'path' => $csrfFlags['path'],
            'secure' => $isSecureRequest,
            'httponly' => $csrfFlags['httponly'],
            'samesite' => 'Lax',
        ]
    );
}

$controller = new DashboardController($pdo, $tenantId, 'staff');
$response = $controller->handle(['method' => $method, 'path' => $path]);

http_response_code($response['status']);
header('Content-Type: text/html; charset=utf-8');

if ($response['status'] === 200) {
    echo $response['body']['html'];
} else {
    echo htmlspecialchars($response['body']['message'] ?? 'Error.', ENT_QUOTES | ENT_HTML5, 'UTF-8');
}
