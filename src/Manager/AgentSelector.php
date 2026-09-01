<?php

declare(strict_types=1);

namespace App\Manager;

use App\Agents\AgentRegistry;

final class AgentSelector
{
    public function __construct(
        private readonly AgentRegistry $registry,
    ) {
    }

    /**
     * Selects the best agent for a task based on purpose and required tools.
     *
     * @param list<string> $requiredTools
     */
    public function select(string $purpose, array $requiredTools = []): void
    {
        // Stub: AgentRegistry doesn't expose a list/query-by-capability method yet.
    }

    public function tenantId(): int
    {
        return $this->registry->tenantId();
    }
}
