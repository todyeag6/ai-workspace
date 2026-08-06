<?php

declare(strict_types=1);

namespace App\Agents;

use UnexpectedValueException;

/**
 * One immutable row of `agent_versions` (FR-AGENT-003).
 *
 * Immutability is the point of the class, so it is enforced twice over:
 * every property is readonly, and allowedTools() hands back a PHP array (a
 * value type, copied on assignment) rather than a shared object. A caller can
 * therefore append to what it received and change nothing - which is the
 * behaviour AC-002 needs, because "the tools this version may use" must not be
 * widenable by whoever happens to be holding a reference to it.
 *
 * The row is only ever constructed FROM the database, never mutated back into
 * it: App\Agents\AgentVersionRepository has no update path at all.
 *
 * © AI WebScapes 2026
 */
final class AgentVersion
{
    /**
     * @param list<string>               $allowedTools
     * @param array<string, scalar|null> $modelConfig
     */
    private function __construct(
        private readonly int $id,
        private readonly int $agentId,
        private readonly int $versionNumber,
        private readonly string $systemPrompt,
        private readonly array $allowedTools,
        private readonly array $modelConfig,
        private readonly string $createdAt
    ) {
    }

    /**
     * @param array<string, scalar|null> $row
     */
    public static function fromRow(array $row): self
    {
        return new self(
            self::int($row, 'id'),
            self::int($row, 'agent_id'),
            self::int($row, 'version_number'),
            self::string($row, 'system_prompt'),
            JsonColumn::decodeList(self::string($row, 'allowed_tools')),
            JsonColumn::decodeMap(self::string($row, 'model_config')),
            self::string($row, 'created_at')
        );
    }

    public function id(): int
    {
        return $this->id;
    }

    public function agentId(): int
    {
        return $this->agentId;
    }

    public function versionNumber(): int
    {
        return $this->versionNumber;
    }

    public function systemPrompt(): string
    {
        return $this->systemPrompt;
    }

    /**
     * @return list<string>
     */
    public function allowedTools(): array
    {
        return $this->allowedTools;
    }

    /**
     * @return array<string, scalar|null>
     */
    public function modelConfig(): array
    {
        return $this->modelConfig;
    }

    public function createdAt(): string
    {
        return $this->createdAt;
    }

    /**
     * @param array<string, scalar|null> $row
     */
    private static function int(array $row, string $column): int
    {
        $value = $row[$column] ?? null;
        if ($value === null || is_bool($value)) {
            throw self::missing($column);
        }

        return (int) $value;
    }

    /**
     * @param array<string, scalar|null> $row
     */
    private static function string(array $row, string $column): string
    {
        $value = $row[$column] ?? null;
        if ($value === null || is_bool($value)) {
            throw self::missing($column);
        }

        return (string) $value;
    }

    private static function missing(string $column): UnexpectedValueException
    {
        return new UnexpectedValueException(sprintf(
            'Column "%s" is absent or null in an agent_versions row, which the '
            . 'schema (migrations/002_agents.sql) declares NOT NULL. The row did '
            . 'not come from that table.',
            $column
        ));
    }
}
