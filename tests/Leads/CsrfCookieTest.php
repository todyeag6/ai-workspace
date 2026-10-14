<?php

declare(strict_types=1);

namespace App\Tests\Leads;

use App\Leads\CsrfCookie;
use PHPUnit\Framework\TestCase;

/**
 * Double-submit cookie CSRF protection for the unauthenticated lead form.
 *
 * OWASP CSRF Cheat Sheet § 3.2: for session-less forms, the double-submit
 * cookie pattern is the recommended defence. The server issues a cookie with
 * a random token; the client echoes it in a hidden form field; the server
 * verifies they match. An attacker's cross-site request cannot read the
 * cookie (SameSite=Lax) and cannot guess the token.
 *
 * © AI WebScapes 2026
 */
final class CsrfCookieTest extends TestCase
{
    public function test_token_is_cryptographically_random(): void
    {
        $a = CsrfCookie::generateToken();
        $b = CsrfCookie::generateToken();

        self::assertNotSame($a, $b, 'tokens must be unique');
        self::assertGreaterThanOrEqual(32, strlen($a), 'token must be at least 32 chars');
    }

    public function test_verify_accepts_matching_pair(): void
    {
        $token = CsrfCookie::generateToken();

        self::assertTrue(CsrfCookie::verify($token, $token));
    }

    public function test_verify_rejects_mismatch(): void
    {
        $cookie = CsrfCookie::generateToken();
        $form = CsrfCookie::generateToken();

        self::assertFalse(CsrfCookie::verify($cookie, $form));
    }

    public function test_verify_rejects_empty_form_token(): void
    {
        $cookie = CsrfCookie::generateToken();

        self::assertFalse(CsrfCookie::verify($cookie, ''));
    }

    public function test_verify_rejects_empty_cookie(): void
    {
        $form = CsrfCookie::generateToken();

        self::assertFalse(CsrfCookie::verify('', $form));
    }

    public function test_verify_rejects_both_empty(): void
    {
        self::assertFalse(CsrfCookie::verify('', ''));
    }

    public function test_cookie_name_is_fixed(): void
    {
        self::assertSame('csrf_token', CsrfCookie::COOKIE_NAME);
    }

    public function test_cookie_attributes_are_secure(): void
    {
        // SameSite=Lax blocks cross-site POST cookie sending
        self::assertTrue(CsrfCookie::cookieFlags()['samesite_lax']);
        // HttpOnly=false so JS can read it for the double-submit
        self::assertFalse(CsrfCookie::cookieFlags()['httponly']);
    }
}
