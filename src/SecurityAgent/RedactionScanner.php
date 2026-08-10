<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use RuntimeException;

/**
 * Detects and scrubs sensitive material in evidence before it is stored or
 * displayed (SFR-EVID-002).
 *
 * WHY AN ALLOWLIST OF KINDS, NOT A DENYLIST OF PATTERNS. AC-002 is "allowlists,
 * never denylists", and SFR-EVID-002 names the categories it cares about
 * explicitly: secrets, session identifiers, personal data, and unnecessary
 * response bodies. So the scanner reasons about KINDS (a fixed, reviewed
 * vocabulary) rather than an open-ended set of "bad strings". A new kind of
 * secret is a deliberate decision to add to the allowlist, not an attacker
 * finding a spelling we forgot.
 *
 * WHY THE SCANNER IS PURE. It touches no database, reads no clock, opens no
 * socket. Given the same input it always returns the same kinds and the same
 * redacted shape, which is what makes every redaction path provable in a unit
 * test without a scanner, a tenant, or a network.
 *
 * WHY A REDACTED VALUE IS A FIXED MARKER, NOT THE ORIGINAL. Once a value matches
 * a sensitive kind it is replaced by `<REDACTED:kind>` and the kind is recorded
 * in the one-way fingerprint list. The original value therefore never reaches
 * the evidence row - redaction is not "obscure", it is "remove and label". The
 * kinds list is the only trace that travels, which is exactly what SFR-EVID-002
 * permits a report to show.
 *
 * © AI WebScapes 2026
 */
final class RedactionScanner
{
    /** Kinds SFR-EVID-002 requires to be redacted. This list is the policy. */
    public const KIND_SECRET = 'secret';

    public const KIND_SESSION_TOKEN = 'session_token';

    public const KIND_PERSONAL_DATA = 'personal_data';

    public const KIND_RESPONSE_BODY = 'response_body';

    /** The marker a redacted value is replaced with. Never the original value. */
    private const MARKER = '<REDACTED:%s>';

    /**
     * Keys whose VALUE is by definition a secret, regardless of its shape
     * (allowlist, not a pattern hunt).
     *
     * @var list<string>
     */
    private const SECRET_KEYS = [
        'password',
        'passwd',
        'secret',
        'api_key',
        'apikey',
        'private_key',
        'privatekey',
        'client_secret',
        'access_key',
        'accesskey',
        'token_secret',
    ];

    /**
     * Keys whose VALUE is by definition a session identifier (allowlist).
     *
     * @var list<string>
     */
    private const SESSION_KEYS = [
        'session',
        'sessionid',
        'session_id',
        'token',
        'authtoken',
        'csrf',
        'csrf_token',
        'cookie',
        'set-cookie',
        'jwt',
        'authorization',
    ];

    /**
     * Keys whose VALUE is by definition personal data (allowlist).
     *
     * @var list<string>
     */
    private const PERSONAL_KEYS = [
        'email',
        'user',
        'username',
        'name',
        'full_name',
        'customer',
        'customer_id',
        'ssn',
    ];

    /**
     * Keys whose VALUE is an unnecessary response body (allowlist). SFR-EVID-002
     * says unnecessary response bodies shall be redacted; these are the bodies.
     *
     * @var list<string>
     */
    private const RESPONSE_BODY_KEYS = [
        'response_body',
        'body',
        'raw_response',
        'html',
        'page_source',
    ];

    /**
     * A secret-VALUE pattern (cloud provider keys). Used only to CATCH a secret
     * carried under an unanticipated key; the key allowlists above are the
     * primary gate. Pattern is narrow and intentional, not a fishing expedition.
     */
    private const SECRET_VALUE_PATTERN = '/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\b[a-z0-9]{32,}\.(?:apps|googleusercontent)\.com\b/i';

    /**
     * A session-token VALUE pattern (JWT-ish). Narrow and
     * intentional - a JWT has a recognised three-part structure, so matching
     * it is high-precision and does not false-positive on every long hex
     * string. (A broad "32+ hex" rule would redact benign banners.)
     */
    private const SESSION_VALUE_PATTERN = '/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/';

    /**
     * A personal-data VALUE pattern (email). Narrow and intentional.
     */
    private const EMAIL_VALUE_PATTERN = '/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i';

    /**
     * Scans structured evidence content and returns the DISTINCT kinds of
     * sensitive data found, in a stable order.
     *
     * @param array<string, mixed> $content The content to inspect (response
     *                                      metadata and/or reproduction).
     * @return list<string> The detected kinds, de-duplicated and sorted.
     */
    public function scan(array $content): array
    {
        $kinds = [];

        foreach ($content as $key => $value) {
            $keyName = strtolower(trim((string) $key));
            $kinds = array_merge($kinds, $this->kindsForKey($keyName, $value));
        }

        return $this->distinct($kinds);
    }

    /**
     * Returns a copy of $content with every sensitive value replaced by its
     * redaction marker. The returned array keeps the same structure so the
     * evidence remains machine-readable (SFR-SCAN-002) - just without secrets.
     *
     * @param array<string, mixed> $content
     * @return array<string, mixed>
     */
    public function redact(array $content): array
    {
        $out = [];
        foreach ($content as $key => $value) {
            $keyName = strtolower(trim((string) $key));
            $kinds = $this->kindsForKey($keyName, $value);

            if ($kinds === [] || !is_string($value)) {
                $out[$key] = $value;
                continue;
            }

            // The first kind wins for the marker label; the value is gone either
            // way. The full set of kinds is still recorded by the caller.
            $out[$key] = sprintf(self::MARKER, $kinds[0]);
        }

        return $out;
    }

    /**
     * @return list<string>
     */
    private function kindsForKey(string $keyName, mixed $value): array
    {
        $kinds = [];

        if ($value === null || !is_scalar($value)) {
            return $kinds;
        }

        $text = (string) $value;

        if (in_array($keyName, self::SECRET_KEYS, true)) {
            $kinds[] = self::KIND_SECRET;
        }
        if (in_array($keyName, self::SESSION_KEYS, true)) {
            $kinds[] = self::KIND_SESSION_TOKEN;
        }
        if (in_array($keyName, self::PERSONAL_KEYS, true)) {
            $kinds[] = self::KIND_PERSONAL_DATA;
        }
        if (in_array($keyName, self::RESPONSE_BODY_KEYS, true)) {
            $kinds[] = self::KIND_RESPONSE_BODY;
        }

        // Value-pattern catches for keys NOT in the allowlists above.
        if ($kinds === []) {
            if (preg_match(self::SECRET_VALUE_PATTERN, $text) === 1) {
                $kinds[] = self::KIND_SECRET;
            } elseif (preg_match(self::SESSION_VALUE_PATTERN, $text) === 1) {
                $kinds[] = self::KIND_SESSION_TOKEN;
            } elseif (preg_match(self::EMAIL_VALUE_PATTERN, $text) === 1) {
                $kinds[] = self::KIND_PERSONAL_DATA;
            }
        }

        return $kinds;
    }

    /**
     * @param array<array-key, mixed> $kinds
     * @return list<string>
     */
    private function distinct(array $kinds): array
    {
        $seen = [];
        foreach ($kinds as $kind) {
            if (is_string($kind) && $kind !== '') {
                $seen[$kind] = true;
            }
        }

        $out = array_keys($seen);
        sort($out);

        return $out;
    }

    /**
     * Builds the canonical redaction marker for a kind (exposed so tests and
     * reports agree on the spelling).
     */
    public static function markerFor(string $kind): string
    {
        if (trim($kind) === '') {
            throw new RuntimeException('A redaction marker needs a kind.');
        }

        return sprintf(self::MARKER, $kind);
    }
}
