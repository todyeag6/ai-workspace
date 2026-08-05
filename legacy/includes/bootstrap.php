<?php declare(strict_types=1);
/**
 * © AI WebScapes 2026
 */

$config = require dirname(__DIR__) . '/config/app.php';
$GLOBALS['config'] = $config;

$isHttps = (
    (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https')
);

session_name('AIWEBSCAPESSESSID');

session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => '',
    'secure' => $isHttps,
    'httponly' => true,
    'samesite' => 'Lax',
]);

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

$sessionTtl = (int) $config['security']['session_ttl_seconds'];

if (isset($_SESSION['last_activity']) && time() - (int) $_SESSION['last_activity'] > $sessionTtl) {
    $_SESSION = [];
    session_destroy();
    session_start();
}

$_SESSION['last_activity'] = time();

require_once __DIR__ . '/security.php';
require_once __DIR__ . '/csrf.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/db.php';

secure_headers();