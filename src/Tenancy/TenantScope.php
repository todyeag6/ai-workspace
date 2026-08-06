<?php

declare(strict_types=1);

namespace App\Tenancy;

use PDO;
use PDOStatement;

/**
 * A validated tenant boundary, and the only place the tenant predicate is
 * spelled out.
 *
 * FR-TEN-002 requires mandatory tenant scoping on all client-data access.
 * The strategy is to make the unscoped state unrepresentable rather than to
 * check for it at each call site:
 *
 *   - The constructor is the single gate. An instance cannot exist for a null,
 *     zero or negative tenant, so any code holding a TenantScope is holding
 *     proof that a real tenant was resolved.
 *   - The predicate and the WHERE clause are GENERATED here. Callers never
 *     write `tenant_id = ...` themselves, so they cannot omit, misspell or
 *     comment it out.
 *   - The value is bound through bindTo() as PARAM_INT, never interpolated.
 *
 * WHY the caller's own predicate is parenthesised in where(): a fragment like
 * `a = 1 OR b = 2` appended bare after `AND` would bind as
 * `(tenant AND a = 1) OR b = 2` and reach straight past the tenant boundary.
 * Wrapping it makes an OR inside a caller fragment unable to widen the scope.
 *
 * This class deliberately owns no PDO connection: it describes a boundary,
 * and App\Data\TenantRepository is what applies it to a statement.
 *
 * © AI WebScapes 2026
 */
final class TenantScope
{
    /**
     * The tenant discriminator column. Every client table carries it NOT NULL
     * (see migrations/001_tenants_identity.sql).
     */
    public const COLUMN = 'tenant_id';

    /**
     * The reserved placeholder name. Reserved in the strong sense: callers
     * passing a parameter of this name are rejected, not overridden.
     */
    public const PARAM = 'tenant';

    private int $id;

    /**
     * Accepts ?int rather than int so that a missing tenant fails HERE, loudly
     * and in one place, instead of being coerced to 0 by a caller trying to
     * satisfy a non-nullable signature.
     */
    public function __construct(?int $tenantId)
    {
        if ($tenantId === null) {
            throw UnscopedQueryException::nullTenant();
        }

        if ($tenantId <= 0) {
            throw UnscopedQueryException::nonPositiveTenant($tenantId);
        }

        $this->id = $tenantId;
    }

    public function id(): int
    {
        return $this->id;
    }

    /**
     * The bare scope predicate, e.g. `tenant_id = :tenant`.
     */
    public function predicate(): string
    {
        return self::COLUMN . ' = :' . self::PARAM;
    }

    /**
     * A complete WHERE clause with the tenant predicate FIRST and the caller's
     * own predicate ANDed after it, parenthesised.
     *
     * Returned with a leading space so it concatenates directly onto a
     * statement head without the caller having to think about spacing - one
     * less way to produce `...probeWHERE...`.
     */
    public function where(string $callerPredicate = ''): string
    {
        $clause = ' WHERE ' . $this->predicate();
        $caller = trim($callerPredicate);

        if ($caller === '') {
            return $clause;
        }

        return $clause . ' AND (' . $caller . ')';
    }

    /**
     * Binds the tenant value as an integer.
     *
     * Always called by the repository AFTER the caller's parameters, so that
     * even a caller parameter that somehow reached the statement is overwritten
     * by the real scope rather than the other way round. Belt and braces:
     * rejectCallerBinding() has already refused such a parameter outright.
     */
    public function bindTo(PDOStatement $statement): void
    {
        $statement->bindValue(':' . self::PARAM, $this->id, PDO::PARAM_INT);
    }

    /**
     * Refuses a caller-supplied binding for the reserved tenant placeholder.
     *
     * Accepts both `tenant` and `:tenant` spellings because PDO accepts both.
     *
     * @param array<string, scalar|null> $params
     */
    public function rejectCallerBinding(array $params): void
    {
        foreach (array_keys($params) as $name) {
            if (ltrim($name, ':') === self::PARAM) {
                throw UnscopedQueryException::reservedParameter($name);
            }
        }
    }

    /**
     * Refuses an attempt to WRITE the tenant column (FR-TEN-001: immutable).
     */
    public function rejectTenantColumnWrite(string $column): void
    {
        if (strtolower(trim($column)) === self::COLUMN) {
            throw UnscopedQueryException::immutableTenantColumn($column);
        }
    }
}
