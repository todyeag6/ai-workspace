<?php

declare(strict_types=1);

namespace App\Security;

/**
 * Anything an authorisation decision can be made ABOUT that belongs to exactly
 * one tenant.
 *
 * The interface is one method wide on purpose: the only property authorisation
 * needs from a domain object is the tenant that owns it, and asking for more
 * would couple the security layer to every entity in the system.
 *
 * © AI WebScapes 2026
 */
interface TenantOwned
{
    public function tenantId(): int;
}
