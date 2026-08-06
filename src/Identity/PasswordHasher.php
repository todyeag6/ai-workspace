<?php

declare(strict_types=1);

namespace App\Identity;

/**
 * Argon2id password hashing with transparent rehash-on-cost-upgrade.
 *
 * FR-IDENT-002: hashes are produced with PASSWORD_ARGON2ID and verified with
 * password_verify(). needsRehash() lets callers detect a stored hash whose
 * cost parameters are weaker than the current policy, so a credential can be
 * re-hashed on the next successful login (permit cost upgrades).
 *
 * Pitfall: Argon2id is configured with memory_cost / time_cost / threads -
 * NOT bcrypt's single "cost". Passing the wrong key silently does nothing.
 *
 * © AI WebScapes 2026
 */
final class PasswordHasher
{
    /**
     * @var array{memory_cost:int,time_cost:int,threads:int}
     */
    private array $options;

    /**
     * @param array{memory_cost?:int,time_cost?:int,threads?:int} $options
     *     Any subset of the argon2id keys; absent keys fall back to defaults:
     *     memory_cost (default 65536 KiB), time_cost (default 4), threads (default 1).
     */
    public function __construct(array $options = [])
    {
        $this->options = [
            'memory_cost' => $options['memory_cost'] ?? PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'time_cost' => $options['time_cost'] ?? PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'threads' => $options['threads'] ?? PASSWORD_ARGON2_DEFAULT_THREADS,
        ];
    }

    /**
     * Hashes a plain-text password with argon2id.
     *
     * password_hash() is documented as returning a non-falsy string for a
     * supported algorithm, so no dead false-branch is added here.
     */
    public function hash(string $plain): string
    {
        return password_hash($plain, PASSWORD_ARGON2ID, $this->options);
    }

    /**
     * Verifies a plain-text password against a stored hash.
     *
     * Returns false for malformed or empty hashes rather than raising, so a
     * corrupted/empty credential can never be reported as a valid match.
     */
    public function verify(string $plain, string $hash): bool
    {
        if ($hash === '') {
            return false;
        }

        return password_verify($plain, $hash);
    }

    /**
     * Reports whether $hash was produced with parameters weaker than the
     * current policy, i.e. it should be re-hashed on the next successful login.
     */
    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, PASSWORD_ARGON2ID, $this->options);
    }
}
