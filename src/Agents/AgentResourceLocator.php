<?php

declare(strict_types=1);

namespace App\Agents;

use App\Security\ResourceLocator;
use App\Security\Subject;
use App\Security\TenantOwned;
use PDO;

/**
 * Resolves an agent id to a tenant-owned object for TenantAuthMiddleware
 * (AC-001).
 *
 * THE NULL IS THE WHOLE CONTRACT. App\Security\ResourceLocator requires that
 * "does not exist" and "belongs to another tenant" produce the same answer, and
 * this class inherits that property rather than re-implementing it:
 * AgentRepository extends TenantRepository, whose findAgent() already collapses
 * both cases to null because the tenant predicate is in the statement and the
 * value is bound by the repository. There is deliberately no second query path
 * here - a locator that wrote its own SQL could drift from that guarantee, and
 * the guarantee is what stops the id space of other tenants being enumerated.
 *
 * WHY A NON-NUMERIC ID RETURNS NULL INSTEAD OF CASTING. `(int) '12abc'` is 12
 * and `(int) 'abc'` is 0, so a careless cast turns caller-supplied junk into a
 * lookup for row 0 or row 12 - a real row, belonging to someone. Refusing the
 * shape before the query keeps every malformed id inside the "unavailable"
 * answer the middleware already maps to a single 403.
 *
 * WHY THIS CLASS HAS NO TENANT OF ITS OWN. It is constructed with a PDO and
 * nothing else, and takes the tenant from the SUBJECT on every call. An earlier
 * draft also accepted a tenant id in the constructor; static analysis (PHPStan
 * L8, property.onlyWritten) correctly reported it as never read, because
 * locating by the subject is the right thing to do - and keeping an unused
 * second scope around is worse than dead code: it is a way for the two to
 * disagree, with the wrong one winning at whichever call site remembered to use
 * it. The subject's tenant is set by the server-side session (FR-IDENT-003) and
 * is not caller-controlled, so it is the only scope worth consulting.
 *
 * © AI WebScapes 2026
 */
final class AgentResourceLocator implements ResourceLocator
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function locate(Subject $subject, string $objectId): ?TenantOwned
    {
        // Shape check first, so malformed input never reaches SQL as a number.
        if ($objectId === '' || !ctype_digit($objectId)) {
            return null;
        }

        $agent = (new AgentRepository($this->pdo, $subject->tenantId()))->findAgent((int) $objectId);

        if ($agent === null) {
            // Missing, or another tenant's. One answer for both (AC-001).
            return null;
        }

        $tenantId = $agent['tenant_id'] ?? null;
        if (!is_int($tenantId) && !is_string($tenantId)) {
            // A row without a usable tenant id cannot be authorised against;
            // refusing is the fail-safe direction.
            return null;
        }

        return new LocatedAgent((int) $tenantId);
    }
}
