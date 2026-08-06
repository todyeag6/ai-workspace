<?php

declare(strict_types=1);

namespace App\Tenancy;

use RuntimeException;

/**
 * Raised when client data would be reached without a usable tenant scope, or
 * when a caller tries to take control of the scope away from the repository.
 *
 * FR-TEN-002 treats an unscoped query as a security defect, not a bad request,
 * so this is thrown rather than returned: there is no sensible "empty result"
 * fallback. A query that cannot state whose data it is asking for must not run.
 *
 * It extends RuntimeException rather than LogicException on purpose. The
 * tenant id typically arrives from the request context (session, token, host
 * header), so a null or 0 here is most often a runtime resolution failure -
 * the context was never populated - not a mistake fixed by reading the code.
 * Either way the fail-closed response is identical.
 *
 * © AI WebScapes 2026
 */
final class UnscopedQueryException extends RuntimeException
{
    public static function nullTenant(): self
    {
        return new self(
            'Refusing to build a client-data query with a null tenant id. '
            . 'FR-TEN-002 requires every query to name the tenant it belongs to; '
            . 'resolve the tenant from the request context before constructing '
            . 'the repository.'
        );
    }

    /**
     * 0 and negatives get their own message because 0 is the genuinely
     * dangerous value: it is falsy, it is what (int) yields for an absent or
     * non-numeric input, and `WHERE tenant_id = 0` is valid SQL that quietly
     * matches nothing instead of failing.
     */
    public static function nonPositiveTenant(int $tenantId): self
    {
        return new self(sprintf(
            'Refusing to build a client-data query for tenant id %d. Tenant ids '
            . 'are positive integers; %d is almost always an unresolved or '
            . 'miscast context value, and it would produce a silently empty '
            . 'result set rather than an error.',
            $tenantId,
            $tenantId
        ));
    }

    /**
     * The caller tried to bind the reserved tenant placeholder itself.
     *
     * Ignoring the parameter silently would be worse than failing: the caller
     * would carry on believing it had selected a tenant.
     */
    public static function reservedParameter(string $name): self
    {
        return new self(sprintf(
            'Parameter ":%s" is reserved: the tenant scope is bound by the '
            . 'repository itself so that no caller can widen or redirect it. '
            . 'Construct a repository for the tenant you mean to read instead.',
            ltrim($name, ':')
        ));
    }

    /**
     * The caller tried to write the tenant column.
     *
     * FR-TEN-001 makes the scope immutable: a row may not be handed to another
     * tenant, because that bypasses AC-001 from inside a legitimate scope.
     */
    public static function immutableTenantColumn(string $column): self
    {
        return new self(sprintf(
            'Column "%s" carries the tenant scope and is immutable (FR-TEN-001). '
            . 'A row cannot be moved between tenants by an UPDATE; delete it in '
            . 'one scope and insert it in the other if that is genuinely intended.',
            $column
        ));
    }
}
