<?php

declare(strict_types=1);

namespace App\Data;

use App\Identity\UserRecord;

/**
 * Tenant-scoped access to the users table.
 *
 * WHY A REPOSITORY AND NOT A DIRECT QUERY IN AuthService. Login looks like the
 * one place a global "find this email" makes sense - it does not. Users are
 * unique per (tenant_id, email) since migration 001, so the same address can
 * belong to two tenants, and an unscoped lookup would authenticate the wrong
 * person. Extending App\Data\TenantRepository makes that impossible: the
 * instance cannot exist without a tenant, and the SELECT carries the predicate
 * whether or not anyone remembers it (FR-TEN-002, AC-001).
 *
 * © AI WebScapes 2026
 */
final class UserRepository extends TenantRepository
{
    protected function table(): string
    {
        return 'users';
    }

    /**
     * @return list<string>
     */
    protected function columns(): array
    {
        return [
            'id',
            'tenant_id',
            'email',
            'password_hash',
            'role',
            'is_active',
            'status',
            'failed_logins',
            'locked_until',
            'mfa_secret',
        ];
    }

    public function findByEmail(string $email): ?UserRecord
    {
        $rows = $this->selectScoped('email = :email', ['email' => $email]);

        return $rows === [] ? null : UserRecord::fromRow($rows[0]);
    }

    public function findById(int $userId): ?UserRecord
    {
        $rows = $this->selectScoped('id = :id', ['id' => $userId]);

        return $rows === [] ? null : UserRecord::fromRow($rows[0]);
    }

    /**
     * FR-IDENT-004: persists the failure counter and, once the threshold is
     * reached, the lock expiry. Both live in the database rather than in the
     * session, so discarding the session cookie does not clear them.
     */
    public function recordFailedLogin(int $userId, int $failedLogins, ?string $lockedUntil): int
    {
        return $this->updateScoped(
            ['failed_logins' => $failedLogins, 'locked_until' => $lockedUntil],
            'id = :id',
            ['id' => $userId]
        );
    }

    /**
     * Clears the lockout state on a successful authentication.
     */
    public function recordSuccessfulLogin(int $userId, string $at): int
    {
        return $this->updateScoped(
            ['failed_logins' => 0, 'locked_until' => null, 'last_login_at' => $at],
            'id = :id',
            ['id' => $userId]
        );
    }

    /**
     * FR-IDENT-002: transparent rehash when the stored cost parameters fall
     * behind current policy.
     */
    public function updatePasswordHash(int $userId, string $passwordHash): int
    {
        return $this->updateScoped(
            ['password_hash' => $passwordHash],
            'id = :id',
            ['id' => $userId]
        );
    }
}
