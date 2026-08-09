<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use InvalidArgumentException;
use RuntimeException;

/**
 * Encrypts the credentials an authorized engagement is allowed to use
 * (SFR-AUTH-003: "credentials shall be stored as scoped secrets and never
 * included in reports or logs").
 *
 * WHY THE KEY IS INJECTED, NOT READ FROM THE ENVIRONMENT
 * -----------------------------------------------------
 * The class takes its key as a constructor argument and reads no global state.
 * Two reasons, and the second is the important one:
 *   1. it is testable without provisioning a process-wide secret, and
 *   2. a class that fetches its own key decides for itself which key it is
 *      using. Injection makes the key a wiring decision made once, visibly, by
 *      the composition root - so "which key encrypted this row" is answerable
 *      by reading the wiring rather than by guessing at environment state.
 *
 * WHY AES-256-GCM
 * ---------------
 * Authenticated encryption. A stored credential must be tamper-EVIDENT, not
 * merely unreadable: with GCM a modified ciphertext fails to decrypt instead of
 * silently yielding different plaintext. The IV is fresh random bytes per
 * encryption, so encrypting the same secret twice produces different payloads
 * and the ciphertext column leaks no equality information between rows.
 *
 * PAYLOAD LAYOUT: base64( iv[12] || tag[16] || ciphertext ), prefixed 'v1:'.
 * The version prefix exists so a future algorithm change is detectable rather
 * than a decryption failure of unknown cause.
 *
 * WHAT THE FINGERPRINT IS FOR: a report has to be able to say WHICH credential
 * a scan used without being able to say what it is. A truncated SHA-256 does
 * that - it is stable, comparable, and one-way.
 *
 * © AI WebScapes 2026
 */
final class ScopedSecretStore
{
    private const CIPHER = 'aes-256-gcm';

    private const PREFIX = 'v1:';

    private const KEY_BYTES = 32;

    private const IV_BYTES = 12;

    private const TAG_BYTES = 16;

    public function __construct(private readonly string $key)
    {
        // Refuse a short or absent key at CONSTRUCTION: a weak key discovered
        // at encryption time would already have a secret in hand.
        if (strlen($this->key) !== self::KEY_BYTES) {
            throw new InvalidArgumentException(sprintf(
                'A scoped secret key must be exactly %d bytes; %d given.',
                self::KEY_BYTES,
                strlen($this->key)
            ));
        }
    }

    public function encrypt(string $secret): string
    {
        if ($secret === '') {
            throw new InvalidArgumentException('Refusing to encrypt an empty secret.');
        }

        $iv = random_bytes(self::IV_BYTES);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $secret,
            self::CIPHER,
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            self::TAG_BYTES
        );

        if ($ciphertext === false) {
            throw new RuntimeException('Failed to encrypt a scoped secret.');
        }

        return self::PREFIX . base64_encode($iv . $tag . $ciphertext);
    }

    public function decrypt(string $payload): string
    {
        if (!str_starts_with($payload, self::PREFIX)) {
            throw new InvalidArgumentException('Unrecognised scoped-secret payload version.');
        }

        $raw = base64_decode(substr($payload, strlen(self::PREFIX)), true);
        if ($raw === false || strlen($raw) <= self::IV_BYTES + self::TAG_BYTES) {
            throw new InvalidArgumentException('Malformed scoped-secret payload.');
        }

        $plaintext = openssl_decrypt(
            substr($raw, self::IV_BYTES + self::TAG_BYTES),
            self::CIPHER,
            $this->key,
            OPENSSL_RAW_DATA,
            substr($raw, 0, self::IV_BYTES),
            substr($raw, self::IV_BYTES, self::TAG_BYTES)
        );

        if ($plaintext === false) {
            // GCM authentication failed: wrong key, or the row was tampered
            // with. Both are refusals, and neither is distinguished here.
            throw new RuntimeException('A scoped secret failed authenticated decryption.');
        }

        return $plaintext;
    }

    /**
     * A one-way, comparable identifier for a secret. Safe for reports and
     * logs, which is the entire point (SFR-AUTH-003).
     */
    public function fingerprint(string $secret): string
    {
        return 'sha256:' . substr(hash('sha256', $secret), 0, 16);
    }
}
