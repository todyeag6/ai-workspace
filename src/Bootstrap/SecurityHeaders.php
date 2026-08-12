<?php

declare(strict_types=1);

namespace App\Bootstrap;

/**
 * SEC-004 - secure response headers (CSP, no-referrer, nosniff, frame-deny).
 *
 * The headers were previously emitted inline in public/index.php, which made
 * them untestable. They are extracted here as a fixed, deny-by-default set so a
 * future weakening (e.g. adding script-src 'unsafe-inline' to the CSP) is caught
 * by tests/Bootstrap/SecurityHeadersTest.php rather than slipping into a release.
 *
 * The values are the canonical, restrictive set: a 'self'-only default-src with
 * inline styles permitted (the dashboard inlines its stylesheet for the axe-core
 * served gate), referrer not sent, content-type not sniffed, and never framed.
 *
 * © AI WebScapes 2026
 */
final class SecurityHeaders
{
    /**
     * The exact headers emitted for every response. Order is stable.
     *
     * @var array<string, string>
     */
    public const HEADERS = [
        'Content-Security-Policy' => "default-src 'self'; style-src 'self' 'unsafe-inline'",
        'Referrer-Policy' => 'no-referrer',
        'X-Content-Type-Options' => 'nosniff',
        'X-Frame-Options' => 'DENY',
    ];

    /**
     * @return array<string, string>
     */
    public static function all(): array
    {
        return self::HEADERS;
    }

    /**
     * Emit every header. The sender defaults to PHP's header(); inject a callable
     * in tests to capture instead of sending.
     *
     * @param callable(string, string): void $sender
     */
    public static function apply(callable $sender = null): void
    {
        $emit = $sender ?? static function (string $name, string $value): void {
            header($name . ': ' . $value);
        };

        foreach (self::HEADERS as $name => $value) {
            $emit($name, $value);
        }
    }
}
