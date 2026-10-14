<?php

declare(strict_types=1);

namespace App\Tests\Bootstrap;

use App\Bootstrap\SecurityHeaders;
use App\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * SEC-004 - secure headers, restrictive CSP, output encoding, prepared queries
 * and safe handling. This pins the exact security headers the platform emits for
 * every HTTP response and refuses any weakening (inline scripts, inline styles,
 * or a missing frame-ancestors/form-action directive).
 *
 * frame-ancestors and form-action are asserted explicitly because neither
 * inherits from default-src: a policy without them leaves clickjacking and
 * form-hijacking unprotected even when default-src 'self' is present.
 * See MDN: Content-Security-Policy: frame-ancestors / form-action.
 */
final class SecurityHeadersTest extends TestCase
{
    #[Test]
    public function test_emits_exactly_the_required_headers(): void
    {
        $captured = [];
        SecurityHeaders::apply(static function (string $name, string $value) use (&$captured): void {
            $captured[$name] = $value;
        });

        self::assertSame([
            'Content-Security-Policy' => "default-src 'self'; style-src 'self'; frame-ancestors 'none'; form-action 'self'",
            'Permissions-Policy' => 'camera=(), geolocation=(), microphone=(), payment=(), usb=()',
            'Referrer-Policy' => 'no-referrer',
            'X-Content-Type-Options' => 'nosniff',
            'X-Frame-Options' => 'DENY',
        ], $captured);
    }

    #[Test]
    public function test_csp_allows_no_inline_scripts_or_styles(): void
    {
        $headers = SecurityHeaders::all();

        $csp = $headers['Content-Security-Policy'];
        // No inline execution of any kind: no script-src grant, no unsafe-eval,
        // and - since SEC-004 externalised the dashboard stylesheet - no
        // style-src 'unsafe-inline' either.
        self::assertStringNotContainsString('script-src', $csp);
        self::assertStringNotContainsString("'unsafe-eval'", $csp);
        self::assertStringNotContainsString("'unsafe-inline'", $csp);
        self::assertStringContainsString("style-src 'self'", $csp);
    }

    #[Test]
    public function test_csp_declares_the_two_no_fallback_directives(): void
    {
        $csp = SecurityHeaders::all()['Content-Security-Policy'];

        // These do NOT fall back to default-src. Omitting them is a defect even
        // with a restrictive default-src, so pin them explicitly.
        self::assertStringContainsString("frame-ancestors 'none'", $csp);
        self::assertStringContainsString("form-action 'self'", $csp);
    }

    #[Test]
    public function test_headers_emitted_once_each_no_duplicates(): void
    {
        $count = 0;
        SecurityHeaders::apply(static function () use (&$count): void {
            $count++;
        });

        self::assertSame(5, $count);
    }

    #[Test]
    public function test_known_header_names_are_exactly_the_required_set(): void
    {
        self::assertSame(
            [
                'Content-Security-Policy',
                'Permissions-Policy',
                'Referrer-Policy',
                'X-Content-Type-Options',
                'X-Frame-Options',
            ],
            array_keys(SecurityHeaders::all())
        );
    }
}
