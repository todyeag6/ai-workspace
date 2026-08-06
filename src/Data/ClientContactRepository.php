<?php

declare(strict_types=1);

namespace App\Data;

/**
 * Tenant-scoped access to client_contacts.
 *
 * It exists at this point in the plan because the authorisation middleware
 * needs a real tenant-owned object to guard, and client_contacts is the client
 * table migration 001 already provides. When P1-T10 adds `leads`, a
 * LeadRepository extends the same base and inherits the same guarantees
 * without re-proving them.
 *
 * © AI WebScapes 2026
 */
final class ClientContactRepository extends TenantRepository
{
    protected function table(): string
    {
        return 'client_contacts';
    }

    /**
     * @return list<string>
     */
    protected function columns(): array
    {
        return ['id', 'tenant_id', 'contact_type', 'name', 'email', 'phone', 'title', 'is_primary'];
    }
}
