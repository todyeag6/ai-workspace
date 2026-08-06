<?php

declare(strict_types=1);

namespace App\Agents;

use RuntimeException;

/**
 * Thrown when an agent id does not resolve INSIDE THE CURRENT TENANT SCOPE.
 *
 * The message deliberately does not distinguish "no such agent" from "an agent
 * belonging to someone else", because a distinguishable answer is an
 * enumeration oracle across tenants (AC-001). The caller learns only that this
 * registry cannot see it.
 *
 * © AI WebScapes 2026
 */
final class UnknownAgent extends RuntimeException
{
    public static function inScope(int $agentId, int $tenantId): self
    {
        return new self(sprintf(
            'No agent %d is visible to tenant %d.',
            $agentId,
            $tenantId
        ));
    }
}
