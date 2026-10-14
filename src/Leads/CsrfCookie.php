<?php

declare(strict_types=1);

namespace App\Leads;

/**
 * Double-submit cookie CSRF token for the unauthenticated lead form.
 *
 * OWASP CSRF Cheat Sheet § 3.2 "No Authentication, No CSRF": for session-less
 * forms, the double-submit cookie pattern is the recommended defence. The
 * server issues a cookie with a cryptographically random token; client-side
 * JS reads it and echoes it in a hidden form field; the server verifies the
 * two match. A cross-site attacker cannot read the cookie (SameSite=Lax)
 * and cannot guess the token.
 *
 * © AI WebScapes 2026
 */
final class CsrfCookie
{
    public const COOKIE_NAME = 'csrf_token';

    private const TOKEN_BYTES = 32;

    public static function generateToken(): string
    {
        return bin2hex(random_bytes(self::TOKEN_BYTES));
    }

    public static function verify(string $cookieToken, string $formToken): bool
    {
        if ($cookieToken === '' || $formToken === '') {
            return false;
        }

        return hash_equals($cookieToken, $formToken);
    }

    /**
     * @return array{samesite_lax: bool, httponly: bool, path: string, secure: bool}
     */
    public static function cookieFlags(): array
    {
        return [
            'samesite_lax' => true,
            'httponly' => false,
            'path' => '/',
            'secure' => false,
        ];
    }
}
