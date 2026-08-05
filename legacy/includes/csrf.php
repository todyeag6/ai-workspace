<?php declare(strict_types=1);
/**
 * © AI WebScapes 2026
 */

function csrf_token(string $scope): string
{
    $config = $GLOBALS['config'];
    $ttl = (int) $config['security']['csrf_ttl_seconds'];

    if (!isset($_SESSION['csrf_tokens'])) {
        $_SESSION['csrf_tokens'] = [];
    }

    $existing = $_SESSION['csrf_tokens'][$scope] ?? null;

    if (
        is_array($existing)
        && isset($existing['token'], $existing['expires'])
        && (int) $existing['expires'] > time()
    ) {
        return $existing['token'];
    }

    $token = bin2hex(random_bytes(32));

    $_SESSION['csrf_tokens'][$scope] = [
        'token' => $token,
        'expires' => time() + $ttl,
    ];

    return $token;
}

function verify_csrf(string $scope, ?string $token): bool
{
    if (!$token || !isset($_SESSION['csrf_tokens'][$scope])) {
        return false;
    }

    $stored = $_SESSION['csrf_tokens'][$scope];

    if (!is_array($stored) || (int) ($stored['expires'] ?? 0) < time()) {
        unset($_SESSION['csrf_tokens'][$scope]);
        return false;
    }

    $valid = hash_equals((string) $stored['token'], $token);

    if ($valid) {
        unset($_SESSION['csrf_tokens'][$scope]);
    }

    return $valid;
}