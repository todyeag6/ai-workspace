<?php declare(strict_types=1);
/**
 * © AI WebScapes 2026
 */

function current_user(): ?array
{
    return $_SESSION['user'] ?? null;
}

function is_logged_in(): bool
{
    return isset($_SESSION['user']) && is_array($_SESSION['user']);
}

function user_role(): string
{
    return $_SESSION['user']['role'] ?? 'guest';
}

function require_login(): void
{
    if (!is_logged_in()) {
        header('Location: /login.php');
        exit;
    }
}

function require_role(array $allowedRoles): void
{
    require_login();

    if (!in_array(user_role(), $allowedRoles, true)) {
        http_response_code(403);
        exit('Access denied.');
    }
}

function login_user(array $user): void
{
    session_regenerate_id(true);

    $_SESSION['user'] = [
        'id' => (int) $user['id'],
        'email' => (string) $user['email'],
        'role' => (string) $user['role'],
    ];
}

function logout_user(): void
{
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();

        setcookie(
            session_name(),
            '',
            [
                'expires' => time() - 42000,
                'path' => $params['path'],
                'domain' => $params['domain'],
                'secure' => (bool) $params['secure'],
                'httponly' => (bool) $params['httponly'],
                'samesite' => $params['samesite'] ?? 'Lax',
            ]
        );
    }

    session_destroy();
}