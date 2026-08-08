<?php

declare(strict_types=1);

namespace App\ManagedOps;

/**
 * The per-agent ownership roster (P2-T4 managed-ops substrate).
 *
 * BR-9.1 [Must] requires every solution to name an update owner and a backup
 * owner; BR-11.1 [Must] requires a business owner, technical owner, data
 * owner, security owner and acceptance authority. This value object carries
 * exactly those accountable parties for one agent version. It is immutable:
 * ownership is reassigned by writing a NEW AgendedOwnership row (the repository
 * is append-only), never by mutating a row - an accountability record you can
 * quietly edit is not an accountability record.
 *
 * It is a plain data object with no PDO/IO, so it is unit-testable without
 * MySQL, mirroring the dashboard read-model and the workflow definition.
 *
 * © AI WebScapes 2026
 */
final class AgentOwnership
{
    /**
     * @param array<string, string> $roles Map of role name => named owner.
     */
    public function __construct(
        public readonly int $agentId,
        public readonly int $versionId,
        public readonly array $roles,
        public readonly string $supportBoundary,
        public readonly string $assignedBy,
        public readonly ?string $assignedAt = null
    ) {
    }

    /**
     * The BR-11.1 accountable roles, in canonical order.
     *
     * @return list<string>
     */
    public static function roleNames(): array
    {
        return [
            'business_owner',
            'technical_owner',
            'data_owner',
            'security_owner',
            'acceptance_authority',
            'update_owner',
            'backup_owner',
        ];
    }

    /**
     * Convenience reader that refuses an unknown role rather than returning
     * null (a typo'd role name should fail loudly, not silently evaluate to
     * "no owner").
     */
    public function ownerOf(string $role): string
    {
        if (!array_key_exists($role, $this->roles)) {
            throw new \InvalidArgumentException(sprintf('Unknown ownership role "%s".', $role));
        }
        return $this->roles[$role];
    }
}
