<?php

declare(strict_types=1);

namespace App\Security;

/**
 * Minimal CSRF guard for state-changing requests.
 *
 * WHY NOT legacy/includes/csrf.php::verify_csrf(). The legacy helper is a
 * procedural function that reads and writes the $_SESSION superglobal. FR-IDENT-003
 * moves sessions server-side into Redis, so there is no $_SESSION for it to
 * consult - reusing it would either reintroduce PHP's file-backed session
 * handler alongside the Redis one or quietly compare a token against an empty
 * array, which returns false in the best case and true in the worst. The token
 * therefore lives on the server-side session record (Subject::csrfToken()) and
 * this class only compares.
 *
 * The comparison uses hash_equals: a plain === leaks the length of the matching
 * prefix through timing, which is enough to reconstruct a token over many
 * requests.
 *
 * © AI WebScapes 2026
 */
final class CsrfGuard
{
    /**
     * Methods defined as safe/idempotent by RFC 9110. Everything else - POST,
     * PUT, PATCH, DELETE and any verb this list has not heard of - is treated
     * as state-changing and needs a token. Unknown verbs default to REQUIRING
     * the token rather than skipping it: fail closed.
     *
     * @var list<string>
     */
    private const SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS', 'TRACE'];

    private const TOKEN_BYTES = 32;

    public function requiresToken(string $httpMethod): bool
    {
        return !in_array(strtoupper(trim($httpMethod)), self::SAFE_METHODS, true);
    }

    /**
     * An empty presented token is refused rather than compared, so a request
     * that simply omits the field cannot match an empty stored token.
     */
    public function verify(string $expected, ?string $presented): bool
    {
        if ($expected === '' || $presented === null || $presented === '') {
            return false;
        }

        return hash_equals($expected, $presented);
    }

    public static function newToken(): string
    {
        return bin2hex(random_bytes(self::TOKEN_BYTES));
    }
}
