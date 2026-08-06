<?php

declare(strict_types=1);

namespace App\Security;

use App\Data\GrantRepository;
use PDO;

/**
 * Role-based access control, DENY BY DEFAULT (SEC-005).
 *
 * The question it answers is narrow: does this subject hold, inside its own
 * tenant, a role that carries the permission code named by $action. Anything
 * that is not a positive answer to that question is false - an unknown action,
 * a subject with no roles, a role granted in another tenant.
 *
 * WHY THE REPOSITORY IS BUILT PER CALL, FROM THE SUBJECT'S TENANT. The grant
 * lookup runs through App\Data\GrantRepository, whose constructor takes the
 * tenant and refuses to exist without one (App\Data\TenantRepository). Building
 * it here, from Subject::tenantId(), means the policy CANNOT be handed a
 * repository scoped to some other tenant by a careless container binding, and
 * the tenant predicate on the lookup is generated rather than written by this
 * class. Scoping stays structural - this class never spells out `tenant_id`.
 *
 * OBJECT TENANCY. When an object is supplied and it is TenantOwned, a tenant
 * mismatch is refused before the permission is even consulted: holding
 * `contact.manage` in tenant 1 says nothing about a contact in tenant 2
 * (AC-001). The middleware repeats this check - two layers, on purpose,
 * because either one alone is a single point of failure for the linchpin
 * property.
 *
 * © AI WebScapes 2026
 */
final class RbacPolicy implements AccessPolicy
{
    public function __construct(private PDO $pdo)
    {
    }

    public function permits(Subject $subject, string $action, ?object $object = null): bool
    {
        if (trim($action) === '') {
            return false;
        }

        if ($object instanceof TenantOwned && $object->tenantId() !== $subject->tenantId()) {
            return false;
        }

        return (new GrantRepository($this->pdo, $subject->tenantId()))
            ->userHasPermission($subject->userId(), $action);
    }
}
