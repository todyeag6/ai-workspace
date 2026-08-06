<?php

declare(strict_types=1);

namespace App\Data;

use App\Security\ResourceLocator;
use App\Security\Subject;
use App\Security\TenantOwned;
use App\Security\TenantResource;
use PDO;

/**
 * Resolves a client contact for an authorisation decision.
 *
 * THE ONE INTERESTING LINE is the repository construction: it is scoped to
 * Subject::tenantId(), the tenant taken from the server-side session. The
 * lookup therefore cannot see another tenant's row at all, and find() returns
 * null identically for "no such contact" and "someone else's contact" - which
 * is what ResourceLocator's contract requires and what stops the 403/404 split
 * from becoming a cross-tenant id oracle (AC-001).
 *
 * The object id is not validated or filtered here on purpose: it is bound as a
 * parameter by the repository, so a hostile string is a miss, not an injection.
 *
 * © AI WebScapes 2026
 */
final class ClientContactLocator implements ResourceLocator
{
    public const TYPE = 'client_contact';

    public function __construct(private PDO $pdo)
    {
    }

    public function locate(Subject $subject, string $objectId): ?TenantOwned
    {
        $row = (new ClientContactRepository($this->pdo, $subject->tenantId()))->find($objectId);

        if ($row === null) {
            return null;
        }

        return new TenantResource(self::TYPE, $objectId, $subject->tenantId());
    }
}
