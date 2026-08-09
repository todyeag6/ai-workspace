<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Data\TenantRepository;

/**
 * Tenant-scoped access to the in-scope asset list (`scan_targets`) that one
 * authorization covers (SBR-3.1 "in-scope assets", SFR-AUTH-002).
 *
 * WHY A SEPARATE REPOSITORY. App\Data\TenantRepository binds one instance to
 * one table, and the tenant predicate is generated from that binding - so the
 * scope list gets its own repository rather than a hand-written statement
 * inside AuthorizationRepository. It is not part of the public surface:
 * AuthorizationRepository owns an instance and delegates, so callers see one
 * aggregate ("an authorization and the targets it authorises") and cannot ask
 * about targets without going through an authorization.
 *
 * WHY THE MATCH IS BINARY-COLLATED. The table's collation is
 * utf8mb4_unicode_ci, under which '/Login' and '/login' compare EQUAL. For a
 * scope decision that is a widening: a path the client never listed would
 * match one they did. Forcing utf8mb4_bin on the comparison makes the match
 * exact, which fails closed. Host case is already handled upstream -
 * TargetCanonicalizer lowercases it - so nothing legitimate is lost.
 *
 * © AI WebScapes 2026
 */
final class ScanTargetRepository extends TenantRepository
{
    private const TARGET_MAX = 512;

    protected function table(): string
    {
        return 'scan_targets';
    }

    /**
     * @return list<string>
     */
    protected function columns(): array
    {
        return [
            'id',
            'tenant_id',
            'authorization_id',
            'raw_target',
            'canonical_target',
            'in_scope',
            'excluded',
        ];
    }

    /**
     * Records a target. The canonical form is computed HERE rather than taken
     * from the caller, so what is stored and what is later matched are
     * produced by the same function (SFR-AUTH-002).
     *
     * @throws \InvalidArgumentException When the target cannot be canonicalized.
     */
    public function add(int $authorizationId, string $rawTarget, bool $inScope = true, bool $excluded = false): int
    {
        $canonical = TargetCanonicalizer::canonicalize($rawTarget);

        return (int) $this->insertScoped([
            'authorization_id' => $authorizationId,
            'raw_target' => mb_substr(trim($rawTarget), 0, self::TARGET_MAX),
            'canonical_target' => mb_substr($canonical, 0, self::TARGET_MAX),
            'in_scope' => $inScope ? 1 : 0,
            'excluded' => $excluded ? 1 : 0,
        ]);
    }

    /**
     * True only when a row exists for THIS tenant and THIS authorization that
     * is marked in-scope and not excluded. Absence is a refusal, so an unknown
     * target - the redirect case - is denied without any extra logic.
     */
    public function isInScope(int $authorizationId, string $canonicalTarget): bool
    {
        $rows = $this->selectScoped(
            'authorization_id = :authorization_id'
            . ' AND canonical_target COLLATE utf8mb4_bin = :canonical_target'
            . ' AND in_scope = 1 AND excluded = 0',
            [
                'authorization_id' => $authorizationId,
                'canonical_target' => $canonicalTarget,
            ]
        );

        return $rows !== [];
    }

    /**
     * Every recorded target for one authorization, for reporting the agreed
     * scope back to the client.
     *
     * @return list<array<string, scalar|null>>
     */
    public function forAuthorization(int $authorizationId): array
    {
        return $this->selectScoped(
            'authorization_id = :authorization_id',
            ['authorization_id' => $authorizationId]
        );
    }
}
