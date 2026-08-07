<?php

declare(strict_types=1);

namespace App\Leads;

use App\Security\CsrfGuard;

/**
 * The HTTP edge of public lead capture.
 *
 * Thin on purpose: it routes, normalises and maps a result onto a status code.
 * Every decision that matters - throttle, honeypot, validation, persist-before-
 * AI - lives in LeadService, so the rules hold no matter which transport calls
 * it, and the tests exercise them without an HTTP server.
 *
 * REQUEST/RESPONSE AS ARRAYS: this codebase has no PSR-7 implementation and no
 * framework kernel, so inventing a request object here would be a second,
 * untested abstraction on the highest-exposure endpoint in Phase 1. The shapes
 * are declared in the docblocks and checked at level 8 instead.
 *
 * CSRF: the endpoint is PUBLIC and UNAUTHENTICATED, so there is usually no
 * session and therefore no server-side token to compare against - which is
 * precisely why LFR-CAP-001/003 put the defence in the honeypot and the shared
 * Redis throttle rather than in a token. When the caller DOES have a session,
 * the expected token is injected and CsrfGuard verifies it, failing closed on
 * an absent or mismatched value. Reused from App\Security\CsrfGuard rather than
 * legacy verify_csrf(), which reads $_SESSION - a superglobal FR-IDENT-003
 * moved server-side into Redis.
 *
 * © AI WebScapes 2026
 */
final class LeadController
{
    public const PATH = '/api/v1/public/leads';

    private const STATUS_NOT_FOUND = 404;

    private const STATUS_METHOD_NOT_ALLOWED = 405;

    private const STATUS_FORBIDDEN = 403;

    /**
     * Fields copied out of the body. An allow-list, not a blocklist: an unknown
     * field never reaches the service, so a caller cannot smuggle `ip_hash` or
     * `source` in and choose its own throttle identity.
     *
     * @var array<string, int> field => maximum length
     */
    private const FIELDS = [
        'name' => 120,
        'email' => 190,
        'company' => 160,
        'automation_need' => 2000,
        'website' => 255,
    ];

    /**
     * @param string      $tenantId          The tenant this public form belongs to.
     * @param string      $ipHashSecret      HMAC key for the throttle identity - the
     *                                       raw IP is never stored or keyed on.
     * @param string|null $expectedCsrfToken The session's token, when there is a
     *                                       session. Null means "anonymous form".
     */
    public function __construct(
        private LeadService $service,
        private string $tenantId,
        private string $ipHashSecret,
        private ?string $expectedCsrfToken = null,
        private ?CsrfGuard $csrf = null
    ) {
    }

    /**
     * @param  array<string, mixed> $request method, path, body, server.
     * @return array{status: int, body: array<string, mixed>}
     */
    public function handle(array $request): array
    {
        $path = $this->stringField($request, 'path');
        if ($path !== self::PATH) {
            return $this->response(self::STATUS_NOT_FOUND, ['message' => 'Not found.']);
        }

        $method = strtoupper($this->stringField($request, 'method'));
        if ($method !== 'POST') {
            return $this->response(self::STATUS_METHOD_NOT_ALLOWED, ['message' => 'Invalid request method.']);
        }

        $body = $this->arrayField($request, 'body');
        $server = $this->arrayField($request, 'server');

        if (!$this->csrfSatisfied($method, $body)) {
            return $this->response(
                self::STATUS_FORBIDDEN,
                ['message' => 'Security validation failed. Refresh the page and try again.']
            );
        }

        $result = $this->service->capture($this->normalise($body, $server), $this->tenantId);

        $payload = [
            'success' => $result['status'] === LeadService::RESULT_ACCEPTED,
            'message' => $result['message'],
            'correlation_id' => $result['correlation_id'],
        ];

        if ($result['errors'] !== []) {
            $payload['errors'] = $result['errors'];
        }

        return $this->response($result['status'], $payload);
    }

    /**
     * Allow-listed, trimmed, whitespace-collapsed and length-capped, mirroring
     * legacy normalize_input(). The honeypot value is normalised too but NOT
     * validated - the service only asks whether it is non-empty.
     *
     * @param  array<string, mixed> $body
     * @param  array<string, mixed> $server
     * @return array<string, string>
     */
    private function normalise(array $body, array $server): array
    {
        $input = [];

        foreach (self::FIELDS as $field => $maxLength) {
            $input[$field] = $this->normalizeInput($this->stringField($body, $field), $maxLength);
        }

        $input['source'] = 'public_form';
        $input['ip_hash'] = $this->hashIp($this->clientIp($server));
        $input['user_agent'] = $this->normalizeInput($this->stringField($server, 'HTTP_USER_AGENT'), 255);

        return $input;
    }

    /**
     * @param array<string, mixed> $body
     */
    private function csrfSatisfied(string $method, array $body): bool
    {
        if ($this->expectedCsrfToken === null) {
            return true;
        }

        $guard = $this->csrf ?? new CsrfGuard();
        if (!$guard->requiresToken($method)) {
            return true;
        }

        return $guard->verify($this->expectedCsrfToken, $this->stringField($body, 'csrf_token'));
    }

    /**
     * @param array<string, mixed> $server
     */
    private function clientIp(array $server): string
    {
        $ip = $this->stringField($server, 'REMOTE_ADDR');

        return $ip !== '' ? $ip : '0.0.0.0';
    }

    /**
     * Mirrors legacy hash_ip(): the throttle keys on an HMAC, so the counter
     * never holds a raw address and the keyspace is not enumerable without the
     * secret.
     */
    private function hashIp(string $ip): string
    {
        return hash_hmac('sha256', $ip, $this->ipHashSecret);
    }

    private function normalizeInput(string $value, int $maxLength): string
    {
        $collapsed = preg_replace('/\s+/', ' ', trim($value)) ?? '';

        return mb_substr($collapsed, 0, $maxLength);
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
     * @param  array<string, mixed> $body
     * @return array{status: int, body: array<string, mixed>}
     */
    private function response(int $status, array $body): array
    {
        return ['status' => $status, 'body' => $body];
    }
}
