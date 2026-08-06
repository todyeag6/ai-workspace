<?php

declare(strict_types=1);

namespace App\Agents;

use InvalidArgumentException;
use PDO;

/**
 * The enterprise agent registry (P1-T5).
 *
 * WHAT IT IS FOR. FR-AGENT-001 asks a governance question, not a technical
 * one: for every agent running against client data, who owns it, what is it
 * for, which version is live, how risky is it, which tools may it call, which
 * data classes may it touch, where does it run, and when does it retire. This
 * class is the single place that question is answerable from.
 *
 * THREE PROPERTIES ARE STRUCTURAL, NOT ADVISORY:
 *
 *   1. DISABLED BY DEFAULT (FR-AGENT-002). create() writes status='disabled'
 *      and the column defaults to the same value, so an agent that reaches the
 *      database by any route is switched off. Turning it on requires
 *      activate(..., gatesPassed: true) and nothing else in the codebase
 *      writes 'active'.
 *
 *   2. IMMUTABLE VERSIONS (FR-AGENT-003). updatePrompt() APPENDS a row to
 *      agent_versions and moves the agent's pointer. It never rewrites a
 *      prompt, a model config or an allow-list, and it cannot: the version
 *      repository exposes no update path (see AgentVersionRepository).
 *
 *   3. TENANT SCOPED (AC-001). Both repositories are built HERE from ONE
 *      tenant id, so the pair cannot be mismatched by a caller wiring an
 *      agents repository for tenant A to a versions repository for tenant B.
 *      Both extend App\Data\TenantRepository, so neither can express an
 *      unscoped statement in the first place.
 *
 * WHY activate() TAKES THE GATE VERDICT AS AN ARGUMENT: this class must not be
 * the thing that decides whether a security review happened - that is P1-T8's
 * job, and a registry that evaluated its own gates could be satisfied by
 * fixing the registry. Taking an explicit boolean keeps the decision outside
 * and the refusal inside, which is the direction that fails safe.
 *
 * WHY THERE IS NO TRANSACTION HERE: create() writes two rows, and wrapping
 * them would be tempting. The surrounding request (and the test harness, which
 * wraps every test in a transaction it rolls back) owns the unit of work;
 * opening a nested one would either be silently ignored or break that
 * rollback. Transaction control belongs to the caller that knows the boundary.
 *
 * © AI WebScapes 2026
 */
final class AgentRegistry
{
    /**
     * Mirrors the ENUM in migrations/002_agents.sql. Validated in PHP as well
     * so a bad value is a clear InvalidArgumentException at the call site
     * instead of a truncated-column error from MySQL three frames down.
     *
     * @var list<string>
     */
    private const RISK_CLASSES = ['low', 'medium', 'high', 'critical'];

    /**
     * @var list<string>
     */
    private const DEPLOYMENT_LOCATIONS = ['cloud', 'hybrid', 'client_cloud', 'local'];

    public const STATUS_DISABLED = 'disabled';
    public const STATUS_ACTIVE = 'active';
    public const STATUS_RETIRED = 'retired';

    private AgentRepository $agents;

    private AgentVersionRepository $versions;

    /**
     * @param ?int $tenantId Nullable on purpose: a missing tenant fails here,
     *                       inside TenantScope, rather than being coerced to 0
     *                       by a caller trying to satisfy a non-nullable
     *                       signature. An unscoped registry cannot exist.
     */
    public function __construct(PDO $pdo, ?int $tenantId)
    {
        $this->agents = new AgentRepository($pdo, $tenantId);
        $this->versions = new AgentVersionRepository($pdo, $tenantId);
    }

    public function tenantId(): int
    {
        return $this->agents->tenantId();
    }

    /**
     * Registers an agent and its first version. The agent is DISABLED
     * (FR-AGENT-002) and version 1 is already the pointed-at version, because
     * "which prompt is this agent running" must have an answer from the moment
     * the row exists - status, not the pointer, is what governs whether it may
     * actually run.
     *
     * @param  list<string>               $allowedTools
     * @param  list<string>               $dataClasses
     * @param  array<string, scalar|null> $modelConfig
     * @return int The new agent id.
     */
    public function create(
        string $name,
        string $owner,
        string $purpose,
        string $systemPrompt,
        string $riskClass = 'high',
        array $allowedTools = [],
        array $dataClasses = [],
        array $modelConfig = [],
        string $deploymentLocation = 'cloud',
        ?string $retirementDate = null
    ): int {
        $this->assertOneOf($riskClass, self::RISK_CLASSES, 'risk class');
        $this->assertOneOf($deploymentLocation, self::DEPLOYMENT_LOCATIONS, 'deployment location');

        $agentId = $this->agents->add([
            'name' => $name,
            'owner' => $owner,
            'purpose' => $purpose,
            'risk_class' => $riskClass,
            'data_classes' => JsonColumn::encodeList($dataClasses),
            'deployment_location' => $deploymentLocation,
            // Explicit, even though the column defaults to it. The safety
            // property is then true whether you read the schema or the code.
            'status' => self::STATUS_DISABLED,
            'retirement_date' => $retirementDate,
        ]);

        $versionId = $this->appendVersion($agentId, 1, $systemPrompt, $allowedTools, $modelConfig);
        $this->agents->pointAtVersion($agentId, $versionId);

        return $agentId;
    }

    /**
     * @return array<string, scalar|null>|null Null when the agent is not
     *         visible to this tenant (AC-001).
     */
    public function find(int $agentId): ?array
    {
        return $this->agents->findAgent($agentId);
    }

    public function status(int $agentId): string
    {
        $agent = $this->requireAgent($agentId);

        return (string) ($agent['status'] ?? self::STATUS_DISABLED);
    }

    /**
     * @return list<string>
     */
    public function dataClasses(int $agentId): array
    {
        $agent = $this->requireAgent($agentId);

        return JsonColumn::decodeList((string) ($agent['data_classes'] ?? '[]'));
    }

    /**
     * FR-AGENT-002. The ONLY writer of status='active' in the codebase.
     *
     * @param bool $gatesPassed The release gate verdict, decided elsewhere.
     */
    public function activate(int $agentId, bool $gatesPassed): void
    {
        $agent = $this->requireAgent($agentId);

        if (($agent['status'] ?? null) === self::STATUS_RETIRED) {
            $retirementDate = $agent['retirement_date'] ?? null;

            throw ReleaseGateNotMet::retired(
                $agentId,
                $retirementDate === null ? null : (string) $retirementDate
            );
        }

        if (!$gatesPassed) {
            // Thrown BEFORE any write: a refusal that still touched the row
            // would be worse than no check at all.
            throw ReleaseGateNotMet::gatesNotPassed($agentId);
        }

        $this->agents->setStatus($agentId, self::STATUS_ACTIVE);
    }

    /**
     * Switches an agent off again. Deliberately ungated: stopping an agent is
     * never the risky direction, and requiring a gate to stop one would make
     * the safe action the harder one.
     */
    public function disable(int $agentId): void
    {
        $this->requireAgent($agentId);

        $this->agents->setStatus($agentId, self::STATUS_DISABLED);
    }

    /**
     * FR-AGENT-001's retirement date, recorded as an event rather than a plan:
     * the agent stops here and activate() will refuse it from now on.
     */
    public function retire(int $agentId, string $retirementDate): void
    {
        $this->requireAgent($agentId);

        $this->agents->retire($agentId, $retirementDate);
    }

    /**
     * FR-AGENT-003: a prompt change is a NEW version, never an edit.
     *
     * The allow-list and model config are carried over VERBATIM from the
     * version being superseded. That is the AC-002 seed: changing the words in
     * a prompt must not be a route to changing what the agent may call, so
     * widening tools is simply not expressible through this method.
     *
     * @return AgentVersion The newly appended version, which is now current.
     */
    public function updatePrompt(int $agentId, string $systemPrompt): AgentVersion
    {
        $this->requireAgent($agentId);

        $latest = $this->latestVersion($agentId);
        $nextNumber = $latest === null ? 1 : $latest->versionNumber() + 1;

        $versionId = $this->appendVersion(
            $agentId,
            $nextNumber,
            $systemPrompt,
            $latest === null ? [] : $latest->allowedTools(),
            $latest === null ? [] : $latest->modelConfig()
        );

        $this->agents->pointAtVersion($agentId, $versionId);

        $appended = $this->versions->findVersion($versionId);
        if ($appended === null) {
            throw UnknownAgent::inScope($agentId, $this->tenantId());
        }

        return AgentVersion::fromRow($appended);
    }

    /**
     * Every version of the agent, oldest first.
     *
     * @return list<AgentVersion>
     */
    public function versions(int $agentId): array
    {
        $versions = [];
        foreach ($this->versions->forAgent($agentId) as $row) {
            $versions[] = AgentVersion::fromRow($row);
        }

        usort($versions, static function (AgentVersion $a, AgentVersion $b): int {
            return $a->versionNumber() <=> $b->versionNumber();
        });

        return $versions;
    }

    /**
     * The version the agent's pointer currently names, or null when the agent
     * is invisible to this tenant (AC-001).
     */
    public function activeVersion(int $agentId): ?AgentVersion
    {
        $agent = $this->agents->findAgent($agentId);
        if ($agent === null) {
            return null;
        }

        $pointer = $agent['active_version_id'] ?? null;
        if ($pointer === null || is_bool($pointer)) {
            return $this->latestVersion($agentId);
        }

        $row = $this->versions->findVersion((int) $pointer);

        return $row === null ? null : AgentVersion::fromRow($row);
    }

    public function latestVersion(int $agentId): ?AgentVersion
    {
        $versions = $this->versions($agentId);
        if ($versions === []) {
            return null;
        }

        return $versions[count($versions) - 1];
    }

    /**
     * The active version's allow-list (AC-002 seed).
     *
     * @return list<string>
     */
    public function allowedTools(int $agentId): array
    {
        $version = $this->activeVersion($agentId);

        return $version === null ? [] : $version->allowedTools();
    }

    /**
     * @param  list<string>               $allowedTools
     * @param  array<string, scalar|null> $modelConfig
     */
    private function appendVersion(
        int $agentId,
        int $versionNumber,
        string $systemPrompt,
        array $allowedTools,
        array $modelConfig
    ): int {
        return $this->versions->append([
            'agent_id' => $agentId,
            'version_number' => $versionNumber,
            'system_prompt' => $systemPrompt,
            'allowed_tools' => JsonColumn::encodeList($allowedTools),
            'model_config' => JsonColumn::encodeMap($modelConfig),
        ]);
    }

    /**
     * Resolves an agent inside the tenant scope or refuses to continue.
     *
     * Every mutating method starts here, so a cross-tenant id never reaches a
     * write. The repository would refuse it anyway (0 affected rows), but a
     * silent no-op is indistinguishable from success to the caller, and
     * "nothing happened and nobody said so" is how governance data rots.
     *
     * @return array<string, scalar|null>
     */
    private function requireAgent(int $agentId): array
    {
        $agent = $this->agents->findAgent($agentId);
        if ($agent === null) {
            throw UnknownAgent::inScope($agentId, $this->tenantId());
        }

        return $agent;
    }

    /**
     * @param list<string> $allowed
     */
    private function assertOneOf(string $value, array $allowed, string $label): void
    {
        if (!in_array($value, $allowed, true)) {
            throw new InvalidArgumentException(sprintf(
                'Unknown %s "%s". Allowed: %s.',
                $label,
                $value,
                implode(', ', $allowed)
            ));
        }
    }
}
