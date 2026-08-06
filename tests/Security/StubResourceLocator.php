<?php

declare(strict_types=1);

namespace App\Tests\Security;

use App\Security\ResourceLocator;
use App\Security\Subject;
use App\Security\TenantOwned;

/**
 * A locator that hands back whatever it was constructed with, INCLUDING an
 * object belonging to another tenant.
 *
 * It exists to prove the middleware does not take a located object's tenancy
 * on trust. The production locator (App\Data\ClientContactLocator) reads
 * through a tenant-scoped repository and structurally cannot return a foreign
 * row - but "the current locator is careful" is not a property AC-001 can rest
 * on, so the middleware re-checks and this stub is what makes that re-check
 * observable.
 *
 * Lives in its own file because PSR-1 forbids more than one class per file.
 *
 * © AI WebScapes 2026
 */
final class StubResourceLocator implements ResourceLocator
{
    public function __construct(private ?TenantOwned $object)
    {
    }

    public function locate(Subject $subject, string $objectId): ?TenantOwned
    {
        return $this->object;
    }
}
