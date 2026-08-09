<?php

declare(strict_types=1);

namespace App\VerticalOffering;

use App\ManagedOps\AgentOwnership;
use App\ManagedOps\SlaRecord;
use App\ManagedOps\SupportModel;
use InvalidArgumentException;

/**
 * An immutable description of one packaged vertical offering — a named,
 * repeatable engagement that bundles one or more agents, each with its own
 * ownership roster and SLA targets, plus a support model and a launch workflow
 * (P2-T5).
 *
 * It is a VALUE OBJECT: it validates a raw template array at load time and
 * refuses anything that would be un-launchable (unknown ownership role, unknown
 * SLA type, empty agent list, unknown support tier, unexecutable workflow step
 * vocabulary). Because it is immutable and validation happens in the
 * constructor, a VerticalTemplate instance is, by construction, a template that
 * CAN be launched — the launcher never re-checks the vocabulary.
 *
 * WHY THE CALLER SUPPLIES RAW ARRAYS: like WorkflowBuilder and EvalHarness, the
 * template's job is validation, so its input is typed loosely and narrowed
 * inside. A precise input shape would make phpstan 8 reject the very guards
 * this class exists to run.
 *
 * The single source of valid vocabulary is reused, never re-declared:
 *  - ownership roles  -> AgentOwnership::roleNames()
 *  - SLA types        -> SlaRecord::types()
 *  - support tiers    -> SupportModel::tiers()
 *  - workflow steps   -> WorkflowBuilder (validated by the launcher via the
 *                        builder itself, so this VO only checks shape, not the
 *                        engine vocabulary — that stays in one place).
 *
 * © AI WebScapes 2026
 */
final class VerticalTemplate
{
    /**
     * @param non-empty-list<array<string, mixed>> $agents
     * @param array<string, mixed>                 $support
     * @param array<string, mixed>                 $launchWorkflow
     */
    private function __construct(
        public readonly string $name,
        public readonly string $description,
        public readonly string $purpose,
        public readonly array $agents,
        public readonly array $support,
        public readonly array $launchWorkflow
    ) {
    }

    public function name(): string
    {
        return $this->name;
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $name = self::requireString($data, 'name');
        $description = self::stringOr($data, 'description', '');
        $purpose = self::stringOr($data, 'purpose', 'lead');
        $support = self::requireArray($data, 'support');
        $workflow = self::requireArray($data, 'launch_workflow');
        $agents = self::requireArray($data, 'agents');

        if (count($agents) === 0) {
            throw new InvalidArgumentException('A vertical template must bundle at least one agent.');
        }

        // Validate support tier against the SINGLE source of truth.
        $tier = self::requireString($support, 'tier');
        if (!in_array($tier, SupportModel::tiers(), true)) {
            throw new InvalidArgumentException(sprintf(
                'Unknown support tier "%s". Allowed: %s.',
                $tier,
                implode(', ', SupportModel::tiers())
            ));
        }

        // Validate each bundled agent: roles ⊆ the canonical roster, SLA types
        // must be real SLA types, required scalars present.
        $roles = AgentOwnership::roleNames();
        foreach ($agents as $index => $agent) {
            self::requireString($agent, 'key');
            self::requireString($agent, 'name');
            self::requireString($agent, 'owner');
            self::requireString($agent, 'purpose');
            self::requireString($agent, 'system_prompt');

            $agentRoles = self::requireArray($agent, 'ownership');
            foreach (array_keys($agentRoles) as $role) {
                if (!in_array($role, $roles, true)) {
                    throw new InvalidArgumentException(sprintf(
                        'Unknown ownership role "%s" on agent %d. Allowed: %s.',
                        (string) $role,
                        $index,
                        implode(', ', $roles)
                    ));
                }
            }

            $slaTargets = self::arrayOr($agent, 'sla_targets', []);
            foreach ($slaTargets as $sla) {
                $type = self::requireString($sla, 'type');
                if (!in_array($type, SlaRecord::types(), true)) {
                    throw new InvalidArgumentException(sprintf(
                        'Unknown SLA type "%s" on agent %d. Allowed: %s.',
                        $type,
                        $index,
                        implode(', ', SlaRecord::types())
                    ));
                }
                $target = self::requireNumber($sla, 'target_hours');
                if ($target < 0) {
                    throw new InvalidArgumentException(sprintf('SLA target_hours must be non-negative on agent %d.', $index));
                }
            }

            // Workflow steps get a shape check here; the engine vocabulary
            // (charge/reserve_stock/fail) is enforced by WorkflowBuilder at
            // launch time, so it is not duplicated into this VO.
            $steps = self::requireArray($workflow, 'steps');
            foreach ($steps as $stepIndex => $step) {
                if (!is_array($step) || !isset($step['type'])) {
                    throw new InvalidArgumentException(sprintf('Launch workflow step %d is missing a "type".', $stepIndex));
                }
            }
        }

        /** @var non-empty-list<array<string, mixed>> $agents */
        $agentsTyped = $agents;

        return new self($name, $description, $purpose, $agentsTyped, $support, $workflow);
    }

    /**
     * Loads a template from a PHP config file that returns the array.
     *
     * @throws VertalTemplateLoadFailure When the file is missing/invalid.
     */
    public static function fromFile(string $path): self
    {
        if (!is_file($path)) {
            throw new VertalTemplateLoadFailure(sprintf('Vertical template file not found: %s.', $path));
        }
        $data = require $path;
        if (!is_array($data)) {
            throw new VertalTemplateLoadFailure(sprintf('Vertical template at %s did not return an array.', $path));
        }

        return self::fromArray($data);
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function agents(): array
    {
        return $this->agents;
    }

    /**
     * @return array<string, mixed>
     */
    public function support(): array
    {
        return $this->support;
    }

    /**
     * @return array<string, mixed>
     */
    public function launchWorkflow(): array
    {
        return $this->launchWorkflow;
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function requireString(array $data, string $key): string
    {
        if (!isset($data[$key]) || !is_string($data[$key]) || $data[$key] === '') {
            throw new InvalidArgumentException(sprintf('Template is missing non-empty string field "%s".', $key));
        }

        return $data[$key];
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function stringOr(array $data, string $key, string $default): string
    {
        return isset($data[$key]) && is_string($data[$key]) ? $data[$key] : $default;
    }

    /**
     * @param array<string, mixed> $data
     * @return array<string, mixed>
     */
    private static function requireArray(array $data, string $key): array
    {
        if (!isset($data[$key]) || !is_array($data[$key])) {
            throw new InvalidArgumentException(sprintf('Template is missing array field "%s".', $key));
        }

        return $data[$key];
    }

    /**
     * @param array<string, mixed> $data
     * @param list<array<string, mixed>> $default
     * @return list<array<string, mixed>>
     */
    private static function arrayOr(array $data, string $key, array $default): array
    {
        /** @var list<array<string, mixed>> $value */
        $value = isset($data[$key]) && is_array($data[$key]) ? $data[$key] : $default;

        return $value;
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function requireNumber(array $data, string $key): float
    {
        if (!isset($data[$key]) || !is_numeric($data[$key])) {
            throw new InvalidArgumentException(sprintf('Template is missing numeric field "%s".', $key));
        }

        return (float) $data[$key];
    }
}
