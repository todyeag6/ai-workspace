<?php

declare(strict_types=1);

namespace App\Tests\Bootstrap;

use App\Bootstrap\SecurityHeaders;
use App\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * SEC-004 - secure headers, restrictive CSP, output encoding, prepared queries
 * and safe handling. This pins the four security headers the platform emits for
 * every HTTP response and refuses any weakening (e.g. inline scripts in the CSP).
 */
final class SecurityHeadersTest extends TestCase
{
    #[Test]
    public function test_emits_exactly_the_four_required_headers(): void
    {
        $captured = [];
        SecurityHeaders::apply(static function (string $name, string $value) use (&$captured): void {
            $captured[$name] = $value;
        });

        self::assertSame([
            'Content-Security-Policy' => "default-src 'self'; style-src 'self' 'unsafe-inline'",
            'Referrer-Policy' => 'no-referrer',
            'X-Content-Type-Options' => 'nosniff',
            'X-Frame-Options' => 'DENY',
        ], $captured);
    }

    #[Test]
    public function test_csp_does_not_allow_inline_scripts(): void
    {
        $headers = SecurityHeaders::all();

        $csp = $headers['Content-Security-Policy'];
        // Inline scripts are forbidden: there must be no script-src grant and no
        // unsafe-eval anywhere. The only sanctioned inline source is style-src,
        // which the dashboard needs for its inline stylesheet.
        self::assertStringNotContainsString('script-src', $csp);
        self::assertStringNotContainsString("'unsafe-eval'", $csp);
        self::assertStringContainsString("style-src 'self' 'unsafe-inline'", $csp);
    }

    #[Test]
    public function test_headers_emitted_once_each_no_duplicates(): void
    {
        $count = 0;
        SecurityHeaders::apply(static function () use (&$count): void {
            $count++;
        });

        self::assertSame(4, $count);
    }

    #[Test]
    public function test_known_header_names_are_exactly_the_four(): void
    {
        self::assertSame(
            ['Content-Security-Policy', 'Referrer-Policy', 'X-Content-Type-Options', 'X-Frame-Options'],
            array_keys(SecurityHeaders::all())
        );
    }
}
