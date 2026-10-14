<?php

declare(strict_types=1);

namespace App\Identity;

/**
 * The HTTP edge of operator authentication (FR-IDENT-001/003/004, SEC-005).
 *
 * THIN ON PURPOSE, in the same shape as App\Leads\LeadController: an array in,
 * an array out, so every rule is exercised without an HTTP server. The codebase
 * has no PSR-7 implementation and no framework kernel, so inventing a request
 * object here would be a second, untested abstraction on a credential-
 * accepting endpoint - the highest-exposure surface in this feature.
 *
 * NO MARKUP LIVES HERE. Rendering belongs to App\Console\AgentConsoleView; this
 * class only routes, authenticates and maps onto a status code. That split is
 * what lets the accessibility guarantees be unit-tested without a database.
 *
 * THE FAILURE MESSAGE IS DELIBERATELY UNINFORMATIVE. AuthService::attempt()
 * already collapses "no such account", "wrong password", "locked" and
 * "disabled" into a single boolean, and this controller must not undo that by
 * guessing at a reason. Telling a caller which of the four occurred turns the
 * login form into an account-enumeration oracle: an attacker learns which
 * addresses exist before spending a single guess. The distinction IS recorded -
 * in the audit trail, via AuditLog::loginFailed() - where the operator can see
 * it and the attacker cannot.
 *
 * SESSION IDENTIFIER (NIST SP 800-63B-4 §5.1.1, Browser Cookies). The cookie
 * carries only the opaque session id; it is HttpOnly (SHOULD), SameSite=Lax
 * (SHOULD), Path=/ (SHOULD), and Secure whenever the request arrived over
 * HTTPS (SHALL be accessible only on secure sessions). The session secret
 * itself is 256 bits from random_bytes() in SessionStore, well past the
 * >=64-bit requirement. The token is regenerated on authentication because the
 * privilege level changes from anonymous to authenticated - OWASP Session
 * Management requires renewal after any privilege change, and a fresh session
 * per login is also what defeats session fixation.
 *
 * https://pages.nist.gov/800-63-4/sp800-63b/session/
 * https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
 *
 * © AI WebScapes 2026
 */
final class LoginController
{
    public const PATH = '/login';

    public const LOGOUT_PATH = '/logout';

    /** The session cookie name. Opaque id only - never any personal data. */
    public const COOKIE_NAME = 'aiwebscapes_session';

    private const STATUS_OK = 200;

    private const STATUS_UNAUTHORIZED = 401;

    private const STATUS_METHOD_NOT_ALLOWED = 405;

    private const STATUS_NOT_FOUND = 404;

    /**
     * ONE message for every authentication failure, whatever the cause. See the
     * class docblock: a specific message is an enumeration oracle.
     */
    private const GENERIC_FAILURE = 'Those credentials were not accepted.';

    public function __construct(
        private readonly AuthService $auth,
        private readonly SessionStore $sessions,
        private readonly bool $secureRequest = false
    ) {
    }

    /**
     * @param  array<string, mixed> $request method, path, body, cookies.
     * @return array{status: int, body: array<string, mixed>, headers?: array<string, string>}
     */
    public function handle(array $request): array
    {
        $path = $this->stringField($request, 'path');

        if ($path !== self::PATH && $path !== self::LOGOUT_PATH) {
            return $this->response(self::STATUS_NOT_FOUND, ['message' => 'Not found.']);
        }

        $method = strtoupper($this->stringField($request, 'method'));
        if ($method !== 'GET' && $method !== 'POST') {
            return $this->response(self::STATUS_METHOD_NOT_ALLOWED, ['message' => 'Method not allowed.']);
        }

        if ($path === self::LOGOUT_PATH) {
            if ($method !== 'POST') {
                return $this->response(self::STATUS_METHOD_NOT_ALLOWED, ['message' => 'Method not allowed.']);
            }

            return $this->logout($this->sessionIdFromCookie($request));
        }

        if ($method === 'GET') {
            return $this->response(self::STATUS_OK, ['render' => 'login']);
        }

        return $this->login($this->arrayField($request, 'body'));
    }

    /**
     * The session id the client presented, read from the cookie only.
     *
     * NEVER from a query parameter or header. NIST SP 800-63B-4 §5.1.1 and the
     * OWASP Session Management Cheat Sheet both require limiting the accepted
     * session-ID exchange mechanism to cookies; accepting an id from the URL
     * would let a link carry someone else's session.
     *
     * @param array<string, mixed> $request
     */
    private function sessionIdFromCookie(array $request): string
    {
        $cookies = $this->arrayField($request, 'cookies');
        $value = $cookies[self::COOKIE_NAME] ?? '';

        return is_scalar($value) ? (string) $value : '';
    }

    /**
     * @param array<string, mixed> $body
     * @return array{status: int, body: array<string, mixed>, headers?: array<string, string>}
     */
    private function login(array $body): array
    {
        $email = $this->stringField($body, 'email');
        $password = $this->stringField($body, 'password');

        if ($email === '' || $password === '') {
            // Missing input is not an authentication attempt, so it is not
            // audited as a failure and does not increment the lockout counter.
            // It still returns the generic message rather than naming the
            // missing field, so this branch is not an oracle either.
            return $this->response(self::STATUS_UNAUTHORIZED, ['message' => self::GENERIC_FAILURE]);
        }

        if (!$this->auth->attempt($email, $password)) {
            return $this->response(self::STATUS_UNAUTHORIZED, ['message' => self::GENERIC_FAILURE]);
        }

        $sessionId = $this->auth->currentSessionId();
        if ($sessionId === null) {
            // attempt() reported success but produced no session, which means
            // the session store failed. Refusing is the fail-safe direction:
            // serving an authenticated response without a revocable session
            // would be an unauthenticated surface wearing a login's clothes.
            return $this->response(self::STATUS_UNAUTHORIZED, ['message' => self::GENERIC_FAILURE]);
        }

        return $this->response(
            self::STATUS_OK,
            ['message' => 'Signed in.', 'session_id' => $sessionId],
            ['Set-Cookie' => $this->sessionCookie($sessionId)]
        );
    }

    /**
     * FR-IDENT-004: revocation is SERVER-SIDE. The session record is DELETED,
     * so the id is dead for every container at once. Clearing the cookie alone
     * would leave a stolen cookie working until it expired, which is why the
     * test asserts a post-logout request is refused rather than asserting the
     * cookie was cleared.
     *
     * WHY THE SESSION ID COMES IN AS AN ARGUMENT RATHER THAN FROM
     * AuthService::revoke(). Each HTTP request builds a fresh AuthService, and
     * revoke() acts on that instance's in-memory subject - which is null on a
     * logout request, because logout does not authenticate anyone. Calling
     * revoke() there silently did nothing: a real defect the test caught (the
     * session id still resolved after logout, and the middleware denied with
     * REASON_FORBIDDEN instead of REASON_NO_SESSION). The id is therefore read
     * from the presented cookie and the store is asked to destroy it.
     *
     * @return array{status: int, body: array<string, mixed>, headers?: array<string, string>}
     */
    private function logout(string $sessionId): array
    {
        if ($sessionId !== '') {
            $this->sessions->destroy($sessionId);
        }

        return $this->response(
            self::STATUS_OK,
            ['message' => 'Signed out.'],
            ['Set-Cookie' => $this->expiredCookie()]
        );
    }

    /**
     * The session cookie.
     *
     * Secure is set only when the request is known to be HTTPS: setting Secure
     * on a plain-HTTP dev request would stop the browser sending the cookie at
     * all and the login would appear to succeed then immediately forget the
     * user. In production the request is HTTPS and the flag is present, which
     * is the requirement (SHALL be accessible only on secure sessions).
     */
    private function sessionCookie(string $sessionId): string
    {
        return sprintf(
            '%s=%s; Path=/; HttpOnly; SameSite=Lax%s',
            self::COOKIE_NAME,
            $sessionId,
            $this->secureRequest ? '; Secure' : ''
        );
    }

    private function expiredCookie(): string
    {
        return sprintf(
            '%s=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0%s',
            self::COOKIE_NAME,
            $this->secureRequest ? '; Secure' : ''
        );
    }

    /**
     * @param array<string, mixed> $source
     */
    private function stringField(array $source, string $key): string
    {
        $value = $source[$key] ?? '';

        return is_scalar($value) ? (string) $value : '';
    }

    /**
     * @param  array<string, mixed> $source
     * @return array<string, mixed>
     */
    private function arrayField(array $source, string $key): array
    {
        $value = $source[$key] ?? [];
        if (!is_array($value)) {
            return [];
        }

        $clean = [];
        foreach ($value as $field => $item) {
            if (is_string($field)) {
                $clean[$field] = $item;
            }
        }

        return $clean;
    }

    /**
     * @param  array<string, mixed>  $body
     * @param  array<string, string> $headers
     * @return array{status: int, body: array<string, mixed>, headers?: array<string, string>}
     */
    private function response(int $status, array $body, array $headers = []): array
    {
        $response = ['status' => $status, 'body' => $body];
        if ($headers !== []) {
            $response['headers'] = $headers;
        }

        return $response;
    }
}
