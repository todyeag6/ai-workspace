<?php declare(strict_types=1);
/**
 * © AI WebScapes 2026
 *
 * FR-CONF-001: every credential is read from the environment. No secret,
 * and no placeholder that looks like one, is committed to this file.
 *
 * FR-CONF-002 / SEC-006: the required keys below are validated before the
 * config array is built, so a misconfigured deployment refuses to boot
 * instead of connecting with a blank password or hashing with a blank key.
 *
 * The returned array's shape and key names are unchanged from the baseline -
 * only the values now come from getenv(). Consumers (includes/bootstrap.php,
 * includes/db.php, includes/csrf.php, api/demo-request.php, index.php)
 * continue to work untouched.
 */

use App\Config\Secrets;

// This file is required directly by includes/bootstrap.php, which does not
// load Composer. Pull the autoloader in here - guarded, so nothing is loaded
// twice when the application has already booted through public/index.php.
$autoload = dirname(__DIR__, 2) . '/vendor/autoload.php';

if (!class_exists(Secrets::class, false) && is_file($autoload)) {
    require_once $autoload;
}

if (!class_exists(Secrets::class)) {
    throw new RuntimeException(
        'Composer autoloader unavailable: cannot validate required configuration secrets.'
    );
}

// Fail closed. Missing or blank => MissingSecretException, no boot.
Secrets::validateRequired([
    'DB_HOST',
    'DB_NAME',
    'DB_USER',
    'DB_PASSWORD',
    'APP_KEY',
]);

$secrets = new Secrets(getenv());

/**
 * Reads a non-secret tunable, falling back to the baseline default.
 *
 * Only values that are safe in source get a default; credentials never do.
 */
$setting = static function (string $key, string $default): string {
    $value = getenv($key);

    return ($value === false || $value === '') ? $default : $value;
};

return [
    'app' => [
        'name' => $setting('APP_NAME', 'Aiwebscapes'),
        'env' => $setting('APP_ENV', 'production'),
        'base_url' => $setting('APP_BASE_URL', 'https://aiwebscapes.com'),
        'support_email' => $setting('APP_SUPPORT_EMAIL', 'support@aiwebscapes.com'),
        'owner_email' => $setting('APP_OWNER_EMAIL', 'admin@aiwebscapes.com'),
    ],

    'db' => [
        'host' => $secrets->require('DB_HOST'),
        'name' => $secrets->require('DB_NAME'),
        'user' => $secrets->require('DB_USER'),
        'pass' => $secrets->require('DB_PASSWORD'),
        'charset' => $setting('DB_CHARSET', 'utf8mb4'),
    ],

    'security' => [
        'csrf_ttl_seconds' => (int) $setting('CSRF_TTL_SECONDS', '1800'),
        'session_ttl_seconds' => (int) $setting('SESSION_TTL_SECONDS', '1800'),
        'rate_limit_window_seconds' => (int) $setting('RATE_LIMIT_WINDOW_SECONDS', '300'),
        'rate_limit_max_attempts' => (int) $setting('RATE_LIMIT_MAX_ATTEMPTS', '5'),
        'ip_hash_secret' => $secrets->require('APP_KEY'),
    ],
];
