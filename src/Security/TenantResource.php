<?php

declare(strict_types=1);

namespace App\Security;

/**
 * The minimal tenant-owned object an authorisation check needs: a type, an id
 * and the tenant that owns it.
 *
 * A resource locator returns one of these instead of a full domain entity so
 * that the authorisation path never has to hydrate - or be coupled to - the
 * entity it is guarding.
 *
 * © AI WebScapes 2026
 */
final class TenantResource implements TenantOwned
{
    public function __construct(
        private readonly string $type,
        private readonly string $id,
        private readonly int $tenantId
    ) {
    }

    public function type(): string
    {
        return $this->type;
    }

    public function id(): string
    {
        return $this->id;
    }

    public function tenantId(): int
    {
        return $this->tenantId;
    }
}
