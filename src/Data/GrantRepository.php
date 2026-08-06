<?php

declare(strict_types=1);

namespace App\Data;

/**
 * Tenant-scoped role grants: the edge an RBAC decision traverses.
 *
 * THE LOOKUP. Reading user_roles scoped to the tenant, the WHERE fragment asks
 * whether any of the subject's roles appears among the roles carrying the
 * requested permission code. The join to role_permissions/permissions lives in
 * a subquery rather than in the FROM clause because
 * App\Data\TenantRepository::table() accepts a bare identifier only - and that
 * restriction is load-bearing, not an inconvenience: it is what stops a
 * repository quietly widening its own FROM clause past the tenant predicate.
 *
 * The subquery is contained by TenantScope::where(), which parenthesises the
 * caller fragment, so it can never widen the scope. It is also a compile-time
 * constant declared here - never assembled from input.
 *
 * WHY THE SUBQUERY DOES NOT REPEAT THE TENANT PREDICATE: the outer query is
 * already scoped, so only role_ids granted to this user IN THIS TENANT reach
 * the IN test. Repeating :tenant inside would also bind the same named
 * placeholder twice, which is exactly the sort of driver-dependent behaviour
 * the tenancy layer should not rest on.
 *
 * © AI WebScapes 2026
 */
final class GrantRepository extends TenantRepository
{
    /**
     * Developer-authored constant. The two placeholders are bound by the base
     * class - nothing is interpolated.
     */
    private const CARRIES_PERMISSION = 'user_id = :user_id AND role_id IN ('
        . 'SELECT rp.role_id FROM role_permissions rp'
        . ' INNER JOIN permissions p ON p.id = rp.permission_id'
        . ' WHERE p.code = :permission_code)';

    protected function table(): string
    {
        return 'user_roles';
    }

    /**
     * @return list<string>
     */
    protected function columns(): array
    {
        return ['id', 'tenant_id', 'user_id', 'role_id'];
    }

    /**
     * DENY BY DEFAULT lives here as much as in the policy: the answer is a row
     * count, so "no grant" and "no such permission code" both produce false
     * without a special case.
     */
    public function userHasPermission(int $userId, string $permissionCode): bool
    {
        $rows = $this->selectScoped(
            self::CARRIES_PERMISSION,
            ['user_id' => $userId, 'permission_code' => $permissionCode]
        );

        return $rows !== [];
    }
}
