<?php

declare(strict_types=1);

namespace App\Connectors;

/**
 * An immutable description of an outside system a connector may reach
 * (P2-T2). Sourced from the vetted `connectors` catalogue, never from anything
 * a model supplied - that is the whole point of FR-TOOL-003: the only URLs a
 * connector client will touch are the ones an operator entered in a migration.
 *
 * © AI WebScapes 2026
 */
final class ConnectorSpec
{
    /**
     * @param string $type crm | http | email - selects which client executes.
     */
    public function __construct(
        public readonly string $name,
        public readonly string $type,
        public readonly string $baseUrl
    ) {
    }

    public function equals(ConnectorSpec $other): bool
    {
        return $this->name === $other->name
            && $this->type === $other->type
            && $this->baseUrl === $other->baseUrl;
    }
}
