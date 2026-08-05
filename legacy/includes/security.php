<?php declare(strict_types=1);
/**
 * © AI WebScapes 2026
 */

function secure_headers(): void
{
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()');
    header(
        "Content-Security-Policy: " .
        "default-src 'self'; " .
        "script-src 'self'; " .
        "style-src 'self'; " .
        "img-src 'self' data:; " .
        "font-src 'self'; " .
        "connect-src 'self'; " .
        "form-action 'self'; " .
        "base-uri 'self'; " .
        "frame-ancestors 'none';"
    );
}

function e(?string $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function normalize_input(string $value, int $maxLength = 255): string
{
    $value = trim($value);
    $value = preg_replace('/\s+/', ' ', $value) ?? '';
    return mb_substr($value, 0, $maxLength);
}

function is_valid_email(string $email): bool
{
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false && mb_strlen($email) <= 190;
}

function get_client_ip(): string
{
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function hash_ip(string $ip, string $secret): string
{
    return hash_hmac('sha256', $ip, $secret);
}

/**
 * Shared Redis connection for cross-request state (LFR-CAP-003).
 *
 * Memoised so a single request reuses one connection. The autoloader is
 * already in scope here: includes/bootstrap.php loads config/app.php, which
 * requires vendor/autoload.php, before it requires this file.
 */
function redis_client(): \Predis\Client
{
    static $client = null;

    if ($client instanceof \Predis\Client) {
        return $client;
    }

    if (!class_exists(\Predis\Client::class)) {
        throw new RuntimeException('Redis client unavailable: cannot enforce shared rate limiting.');
    }

    // REDIS_DSN is the connection string this project already publishes to the
    // container (see compose.yaml); the default keeps parity with it.
    $dsn = getenv('REDIS_DSN');

    $client = new \Predis\Client(($dsn === false || $dsn === '') ? 'tcp://redis:6379' : $dsn);

    return $client;
}

function json_response(array $payload, int $statusCode = 200): never
{
    http_response_code($statusCode);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_THROW_ON_ERROR);
    exit;
}