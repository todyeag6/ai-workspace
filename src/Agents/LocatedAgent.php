<?php

declare(strict_types=1);

namespace App\Agents;

use App\Security\TenantOwned;

/**
 * The tenant of a resolved agent, as an authorisation object.
 *
 * WHY A SEPARATE VALUE OBJECT RATHER THAN MAKING AgentResourceLocator ITSELF
 * TenantOwned. ResourceLocator::locate() already receives a Subject; a locator
 * that also claimed a tenantId() would give TenantAuthMiddleware two ways to
 * ask the same question, and the middleware's cross-tenant re-check
 * (`$object->tenantId() !== $subject->tenantId()`) exists precisely to be
 * independent of the locator's own scoping. Returning a bare value object keeps
 * that check meaningful - it compares the RESULT's tenant against the subject,
 * not the locator's configuration against itself.
 *
 * It carries only the tenant, matching TenantOwned's one-method contract: the
 * authorisation layer has no business knowing anything else about an agent, and
 * asking for more would couple security to the agent schema.
 *
 * © AI WebScapes 2026
 */
final class LocatedAgent implements TenantOwned
{
    public function __construct(private readonly int $tenantId)
    {
    }

    public function tenantId(): int
    {
        return $this->tenantId;
    }
}
