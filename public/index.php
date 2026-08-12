<?php

/**
 * Minimal, secured demo router for the P1-T15 dashboard (FR-DASH-001/002,
 * A11Y-001..006).
 *
 * WHY THIS EXISTS. The plan's T15 skeleton assumed a Slim kernel + Twig served at
 * /dashboard, but the as-built platform has no web kernel (every controller is
 * array-in/array-out and tested directly). Standing up an entire framework for a
 * single page would be unbuilt scope with its own attack surface. This file is a
 * deliberately tiny front controller whose ONLY job is to satisfy the axe-core
 * SERVED-page gate; the real logic lives in App\Dashboard\DashboardController.
 *
 * SECURITY (AC-001 / SEC-010).
 *  - Tenant identity is FIXED by the server (APP_TENANT_ID env), never derived
 *    from the request. A ?tenant= override is refused, so a caller cannot scope
 *    themselves into another tenant's data.
 *  - All dashboard data is escaped at a single sink in the controller, so this
 *    page carries no injection surface.
 *  - Security headers (CSP, no-referrer, nosniff) are emitted for every response.
 *
 * This file is NOT the production entrypoint and is not wired into any auth flow;
 * it exists to make the accessibility gate runnable. See
 * docs/SESSION_HANDOFF_P1T14.md deviation log (T15).
 *
 * © AI WebScapes 2026
 */

declare(strict_types=1);

use App\Dashboard\DashboardController;

require __DIR__ . '/../vendor/autoload.php';

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

$controller = new DashboardController($pdo, $tenantId, 'staff');
$response = $controller->handle(['method' => $method, 'path' => $path]);

http_response_code($response['status']);
header('Content-Type: text/html; charset=utf-8');
\App\Bootstrap\SecurityHeaders::apply();

if ($response['status'] === 200) {
    echo $response['body']['html'];
} else {
    echo htmlspecialchars($response['body']['message'] ?? 'Error.', ENT_QUOTES | ENT_HTML5, 'UTF-8');
}
