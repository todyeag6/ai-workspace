<?php

declare(strict_types=1);

namespace App\Data;

/**
 * Single-use password reset tokens, tenant-scoped.
 *
 * ONLY THE HASH IS STORED. The token itself is 32 bytes from random_bytes()
 * and is shown to the user once, by the caller. Storing the hash means a
 * database disclosure yields nothing that can be redeemed, and the lookup is
 * still a single indexed equality test.
 *
 * SINGLE USE IS ENFORCED BY THE WRITE, NOT THE READ. consume() does not
 * "check then update" - it issues an UPDATE whose WHERE clause includes
 * `used_at IS NULL` and treats an affected-row count of 0 as "already
 * redeemed". Two concurrent redemptions therefore cannot both succeed: MySQL
 * decides, not a race between two PHP processes.
 *
 * © AI WebScapes 2026
 */
final class PasswordResetTokenRepository extends TenantRepository
{
    protected function table(): string
    {
        return 'password_reset_tokens';
    }

    /**
     * @return list<string>
     */
    protected function columns(): array
    {
        return ['id', 'tenant_id', 'user_id', 'token_hash', 'expires_at', 'used_at', 'created_at'];
    }

    public function issue(int $userId, string $tokenHash, string $expiresAt): string
    {
        return $this->insertScoped([
            'user_id' => $userId,
            'token_hash' => $tokenHash,
            'expires_at' => $expiresAt,
        ]);
    }

    /**
     * Returns the user id the token belongs to, or null when it is unknown,
     * expired or already used - one answer for every failure, so a caller
     * cannot probe which tokens exist.
     */
    public function consume(string $tokenHash, string $now): ?int
    {
        $rows = $this->selectScoped(
            'token_hash = :token_hash AND used_at IS NULL AND expires_at > :now',
            ['token_hash' => $tokenHash, 'now' => $now]
        );

        if ($rows === []) {
            return null;
        }

        $claimed = $this->updateScoped(
            ['used_at' => $now],
            'token_hash = :token_hash AND used_at IS NULL',
            ['token_hash' => $tokenHash]
        );

        if ($claimed !== 1) {
            // Another request redeemed it between the SELECT and the UPDATE.
            return null;
        }

        $userId = $rows[0]['user_id'] ?? null;

        return is_scalar($userId) ? (int) $userId : null;
    }
}
