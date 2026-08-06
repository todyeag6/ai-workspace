<?php

declare(strict_types=1);

namespace App\Security;

/**
 * Resolves the object an action names, for the subject asking about it.
 *
 * THE IMPORTANT PART OF THIS CONTRACT IS THE NULL. An implementation returns
 * null both when the object does not exist and when it belongs to another
 * tenant, and MUST NOT distinguish the two - not by return value, not by
 * exception type. The caller (TenantAuthMiddleware) maps null to a single 403,
 * so the difference is never observable from outside. Reporting "no such row"
 * separately from "not yours" would let a caller enumerate the id space of
 * every other tenant, which is precisely the hole AC-001 closes.
 *
 * The natural implementation is a lookup through a tenant-scoped repository
 * (App\Data\TenantRepository), which already collapses both cases to null.
 *
 * © AI WebScapes 2026
 */
interface ResourceLocator
{
    public function locate(Subject $subject, string $objectId): ?TenantOwned;
}
