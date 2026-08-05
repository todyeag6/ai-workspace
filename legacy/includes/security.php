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

function json_response(array $payload, int $statusCode = 200): never
{
    http_response_code($statusCode);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_THROW_ON_ERROR);
    exit;
}