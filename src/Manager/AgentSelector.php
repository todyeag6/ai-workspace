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
     * Selects the best active agent for a task based on purpose and required
     * tools. Returns null when no active agent matches — the manager must
     * then create a default agent for the task.
     *
     * @param list<string> $requiredTools
     *
     * @return array{id: int, name: string, owner: string, purpose: string, risk_class: string, allowed_tools: list<string>, model_config: array<string, scalar|null>}|null
     */
    public function select(string $purpose, array $requiredTools = []): ?array
    {
        $candidates = $this->registry->listActive();

        $matchesPurpose = array_filter(
            $candidates,
            static fn (array $agent): bool => $agent['purpose'] === $purpose
        );

        if ($matchesPurpose !== []) {
            foreach ($matchesPurpose as $agent) {
                if ($this->toolsCover($agent['allowed_tools'], $requiredTools)) {
                    return $agent;
                }
            }
        }

        foreach ($candidates as $agent) {
            if ($this->toolsCover($agent['allowed_tools'], $requiredTools)) {
                return $agent;
            }
        }

        return null;
    }

    public function tenantId(): int
    {
        return $this->registry->tenantId();
    }

    /**
     * @param list<string> $agentTools
     * @param list<string> $requiredTools
     */
    private function toolsCover(array $agentTools, array $requiredTools): bool
    {
        if ($requiredTools === []) {
            return true;
        }

        $agentToolSet = array_flip($agentTools);

        foreach ($requiredTools as $tool) {
            if (!isset($agentToolSet[$tool])) {
                return false;
            }
        }

        return true;
    }
}
