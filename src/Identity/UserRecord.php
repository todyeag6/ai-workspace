<?php

declare(strict_types=1);

namespace App\Identity;

/**
 * One users row, narrowed from the repository's `array<string, scalar|null>`
 * into a checked shape.
 *
 * WHY THIS EXISTS: PDO hands back untyped scalars, so without a boundary object
 * every credential decision - is this account locked, how many failures has it
 * had - would be made on `mixed`, and level-8 analysis would be blind from the
 * repository outward. Converting once, here, means AuthService reasons about
 * ints and bools rather than about whatever MySQL happened to return.
 *
 * © AI WebScapes 2026
 */
final class UserRecord
{
    public function __construct(
        private readonly int $id,
        private readonly int $tenantId,
        private readonly string $email,
        private readonly string $passwordHash,
        private readonly int $failedLogins,
        private readonly ?string $lockedUntil,
        private readonly ?string $mfaSecret,
        private readonly string $status,
        private readonly bool $isActive
    ) {
    }

    /**
     * @param array<string, scalar|null> $row
     */
    public static function fromRow(array $row): self
    {
        return new self(
            self::toInt($row['id'] ?? null),
            self::toInt($row['tenant_id'] ?? null),
            self::toString($row['email'] ?? null),
            self::toString($row['password_hash'] ?? null),
            self::toInt($row['failed_logins'] ?? null),
            self::toNullableString($row['locked_until'] ?? null),
            self::toNullableString($row['mfa_secret'] ?? null),
            self::toString($row['status'] ?? null),
            self::toInt($row['is_active'] ?? null) === 1
        );
    }

    public function id(): int
    {
        return $this->id;
    }

    public function tenantId(): int
    {
        return $this->tenantId;
    }

    public function email(): string
    {
        return $this->email;
    }

    public function passwordHash(): string
    {
        return $this->passwordHash;
    }

    public function failedLogins(): int
    {
        return $this->failedLogins;
    }

    /**
     * FR-IDENT-001. Reported, not enforced: the column exists and is carried
     * onto the session so the second-factor challenge is a feature addition
     * rather than a schema migration.
     */
    public function mfaEnrolled(): bool
    {
        return $this->mfaSecret !== null && $this->mfaSecret !== '';
    }

    /**
     * FR-IDENT-004. The lock is a TIMESTAMP in the database rather than a flag
     * in the session, so it survives a new session, a new process and a
     * restart - which is the whole point of a lockout.
     *
     * $now is injected so the boundary can be tested without sleeping.
     */
    public function isLocked(int $now): bool
    {
        if ($this->lockedUntil === null || $this->lockedUntil === '') {
            return false;
        }

        $until = strtotime($this->lockedUntil);

        return $until !== false && $until > $now;
    }

    /**
     * Whether the account may authenticate at all, lockout aside. Both the
     * legacy is_active flag and the richer status column have to agree: 001
     * left is_active in place, so ignoring it would silently re-enable
     * accounts that were disabled before the status column existed.
     */
    public function canAuthenticate(): bool
    {
        return $this->isActive && $this->status === 'active';
    }

    private static function toInt(mixed $value): int
    {
        return is_scalar($value) ? (int) $value : 0;
    }

    private static function toString(mixed $value): string
    {
        return is_scalar($value) ? (string) $value : '';
    }

    private static function toNullableString(mixed $value): ?string
    {
        return is_scalar($value) ? (string) $value : null;
    }
}
