<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use InvalidArgumentException;

/**
 * Canonicalizes a target so that scope matching cannot be fooled by spelling
 * (SFR-AUTH-002: "targets shall be canonicalized and checked against scope
 * before every request").
 *
 * WHY THIS IS PURE AND STATIC
 * ---------------------------
 * It resolves nothing. No DNS, no HTTP, no filesystem - the same reasoning as
 * App\Tools\ToolGateway: a validator that performs a lookup has turned
 * attacker-supplied input into an outbound request, and a scope check that
 * depends on the network is neither deterministic nor testable. The output is
 * a function of the input string alone, so the canonical form stored at
 * authorization time and the one computed for a redirect three hops later are
 * comparable byte for byte.
 *
 * WHAT IS NORMALISED, AND WHY EACH ONE MATTERS
 * -------------------------------------------
 *   - scheme and host lowercased      HTTPS://APP.X != https://app.x textually
 *   - default port dropped            :443 on https is the same endpoint
 *   - trailing dot on the host removed  app.x. is the same name as app.x
 *   - fragment dropped                #frag never reaches the server
 *   - empty path becomes '/'          https://app.x and https://app.x/ are one
 *   - percent-escapes uppercased      %2f and %2F are the same octet
 *   - query preserved verbatim        parameter ORDER is significant to apps,
 *                                     so sorting it would change the target
 *
 * WHAT IS REFUSED OUTRIGHT (throws, and the caller records a denial):
 *   - a scheme other than http/https - nothing else is a web scan target
 *   - userinfo (http://good.test@evil.test/) - the classic parser-confusion
 *     trick where two libraries disagree about which side is the host
 *   - an empty or absent host
 *
 * STATED LIMIT: canonicalization equalises SPELLING, not identity. Two
 * different names resolving to one address remain two targets, deliberately -
 * scope is granted over names the client authorised, not over addresses.
 *
 * © AI WebScapes 2026
 */
final class TargetCanonicalizer
{
    /** @var list<string> */
    private const ALLOWED_SCHEMES = ['http', 'https'];

    /**
     * @throws InvalidArgumentException When the target cannot be canonicalized.
     */
    public static function canonicalize(string $target): string
    {
        $trimmed = trim($target);
        if ($trimmed === '') {
            throw new InvalidArgumentException('An empty target cannot be canonicalized.');
        }

        // A bare host ("app.example.test/login") is read as https, the safer
        // of the two - never as a relative path, which has no meaning here.
        if (preg_match('#^[a-zA-Z][a-zA-Z0-9+.\-]*://#', $trimmed) !== 1) {
            $trimmed = 'https://' . $trimmed;
        }

        $parts = parse_url($trimmed);
        if (!is_array($parts)) {
            throw new InvalidArgumentException(sprintf('Target "%s" is not a parseable URL.', $target));
        }

        if (isset($parts['user']) || isset($parts['pass'])) {
            throw new InvalidArgumentException('A target carrying userinfo is refused: the host is ambiguous.');
        }

        $scheme = strtolower(is_string($parts['scheme'] ?? null) ? $parts['scheme'] : '');
        if (!in_array($scheme, self::ALLOWED_SCHEMES, true)) {
            throw new InvalidArgumentException(sprintf('Target scheme "%s" is not http or https.', $scheme));
        }

        $host = rtrim(strtolower(is_string($parts['host'] ?? null) ? trim($parts['host'], '[]') : ''), '.');
        if ($host === '') {
            throw new InvalidArgumentException(sprintf('Target "%s" names no host.', $target));
        }

        $port = isset($parts['port']) ? (int) $parts['port'] : null;
        $defaultPort = $scheme === 'https' ? 443 : 80;
        $authority = $host;
        if ($port !== null && $port !== $defaultPort) {
            // parse_url() has already refused anything outside 1-65535, so a
            // range check here would be dead code.
            $authority .= ':' . $port;
        }

        $path = is_string($parts['path'] ?? null) ? $parts['path'] : '';
        if ($path === '') {
            $path = '/';
        }

        $query = is_string($parts['query'] ?? null) ? $parts['query'] : '';

        // The fragment is dropped: it is never transmitted, so a scope
        // decision must not depend on it.
        return $scheme . '://' . $authority
            . self::normaliseEscapes($path)
            . ($query === '' ? '' : '?' . self::normaliseEscapes($query));
    }

    /**
     * Best-effort canonical form for logging a target that failed the strict
     * canonicalizer. Never throws: a denial event must always be recordable,
     * including for input too malformed to canonicalize.
     */
    public static function forAudit(string $target): string
    {
        try {
            return self::canonicalize($target);
        } catch (InvalidArgumentException) {
            return trim($target);
        }
    }

    /**
     * Uppercases the hex digits of percent-escapes so %2f and %2F compare
     * equal, without touching (and therefore without decoding) anything else -
     * decoding would merge distinct targets, which is the opposite of what a
     * scope check wants.
     */
    private static function normaliseEscapes(string $value): string
    {
        $normalised = preg_replace_callback(
            '/%([0-9a-fA-F]{2})/',
            static fn (array $m): string => '%' . strtoupper((string) $m[1]),
            $value
        );

        return $normalised ?? $value;
    }
}
