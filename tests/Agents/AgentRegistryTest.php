<?php

declare(strict_types=1);

namespace App\Tests\Agents;

use App\Agents\AgentRegistry;
use App\Agents\AgentRepository;
use App\Agents\AgentVersionRepository;
use App\Agents\ReleaseGateNotMet;
use App\Agents\UnknownAgent;
use App\Data\TenantRepository;
use App\Tenancy\TenantScope;
use App\Tenancy\UnscopedQueryException;
use App\Tests\TestCase;

/**
 * P1-T5: the enterprise agent registry.
 *
 * Three properties are load-bearing and each is proven by a test that would
 * fail if the property were removed, not merely by an assertion that happens
 * to pass today:
 *
 *   FR-AGENT-002  An agent is born DISABLED and activation is refused unless
 *                 the release gates report success. The refusal is proven by
 *                 catching it AND by re-reading the status afterwards - a
 *                 throw that still flipped the row would be worse than none.
 *   FR-AGENT-003  A prompt change APPENDS an immutable version row. Proven by
 *                 the new version carrying a different id while the previous
 *                 row keeps its original prompt verbatim.
 *   AC-001        Agents and their versions are tenant-scoped, so a registry
 *                 for another tenant sees nothing at all - not an error, which
 *                 would itself confirm the row exists.
 *
 * © AI WebScapes 2026
 */
final class AgentRegistryTest extends TestCase
{
    private const OTHER_TENANT = 2;

    private function registry(int $tenantId = 1): AgentRegistry
    {
        return new AgentRegistry($this->pdo, $tenantId);
    }

    private function createAgent(AgentRegistry $registry, string $name = 'Lead Triage'): int
    {
        return $registry->create(
            name: $name,
            owner: 'ops@aiwebscapes.test',
            purpose: 'Triage inbound leads and draft a first reply',
            systemPrompt: 'You triage leads.',
            riskClass: 'high',
            allowedTools: ['crm.read', 'crm.write'],
            dataClasses: ['pii', 'commercial'],
            modelConfig: ['model' => 'gpt-4o-mini', 'temperature' => '0.2'],
            deploymentLocation: 'cloud',
            retirementDate: '2027-01-01'
        );
    }

    /**
     * Seeds a second tenant so the cross-tenant proof has a real foreign key
     * to point at. Written through raw PDO on purpose: a test that could only
     * reach data through the class under test could not falsify it.
     */
    private function seedOtherTenant(): void
    {
        $this->pdo->exec(
            'INSERT IGNORE INTO tenants (id, slug, name, status, deployment_model) '
            . "VALUES (2, 'p1t5-other', 'Other Tenant', 'active', 'cloud')"
        );
    }

    // FR-AGENT-001 ---------------------------------------------------------

    public function test_registry_records_the_full_agent_metadata(): void
    {
        $registry = $this->registry();
        $id = $this->createAgent($registry);

        $agent = $registry->find($id);
        self::assertNotNull($agent);

        self::assertSame('Lead Triage', $agent['name']);
        self::assertSame('ops@aiwebscapes.test', $agent['owner']);
        self::assertSame('Triage inbound leads and draft a first reply', $agent['purpose']);
        self::assertSame('high', $agent['risk_class']);
        self::assertSame('cloud', $agent['deployment_location']);
        self::assertSame('2027-01-01', $agent['retirement_date']);
        self::assertSame(1, (int) $agent['tenant_id']);
        self::assertSame(['pii', 'commercial'], $registry->dataClasses($id));

        $version = $registry->activeVersion($id);
        self::assertNotNull($version);
        self::assertSame(1, $version->versionNumber());
        self::assertSame('You triage leads.', $version->systemPrompt());
        self::assertSame(['model' => 'gpt-4o-mini', 'temperature' => '0.2'], $version->modelConfig());
    }

    // FR-AGENT-002 ---------------------------------------------------------

    public function test_agent_disabled_by_default(): void
    {
        $registry = $this->registry();
        $id = $this->createAgent($registry);

        self::assertSame('disabled', $registry->status($id));

        $agent = $registry->find($id);
        self::assertNotNull($agent);
        self::assertSame('disabled', $agent['status']);
    }

    public function test_activation_blocked_until_gates_pass(): void
    {
        $registry = $this->registry();
        $id = $this->createAgent($registry);

        try {
            $registry->activate($id, gatesPassed: false);
            self::fail('Activation must be refused while the release gates have not passed.');
        } catch (ReleaseGateNotMet $e) {
            self::assertStringContainsString('release gate', strtolower($e->getMessage()));
        }

        // The refusal must leave the row alone: a throw that still flipped the
        // status would be a worse failure than no check at all.
        self::assertSame('disabled', $registry->status($id));
    }

    public function test_activation_succeeds_once_gates_pass(): void
    {
        $registry = $this->registry();
        $id = $this->createAgent($registry);

        $registry->activate($id, gatesPassed: true);

        self::assertSame('active', $registry->status($id));
    }

    public function test_retired_agent_cannot_be_reactivated(): void
    {
        $registry = $this->registry();
        $id = $this->createAgent($registry);
        $registry->retire($id, '2026-12-31');

        self::assertSame('retired', $registry->status($id));

        $this->expectException(ReleaseGateNotMet::class);
        $registry->activate($id, gatesPassed: true);
    }

    // FR-AGENT-003 ---------------------------------------------------------

    public function test_prompt_change_creates_new_version(): void
    {
        $registry = $this->registry();
        $id = $this->createAgent($registry);

        $first = $registry->latestVersion($id);
        self::assertNotNull($first);

        $second = $registry->updatePrompt($id, 'You triage leads and never promise a discount.');

        self::assertNotSame($first->id(), $second->id());
        self::assertSame(2, $second->versionNumber());
        self::assertSame('You triage leads and never promise a discount.', $second->systemPrompt());

        $active = $registry->activeVersion($id);
        $latest = $registry->latestVersion($id);
        self::assertNotNull($active);
        self::assertNotNull($latest);
        self::assertSame($second->id(), $active->id());
        self::assertSame($second->id(), $latest->id());
    }

    public function test_previous_version_row_is_immutable(): void
    {
        $registry = $this->registry();
        $id = $this->createAgent($registry);
        $first = $registry->latestVersion($id);
        self::assertNotNull($first);

        $registry->updatePrompt($id, 'Rewritten.');

        $versions = $registry->versions($id);
        self::assertCount(2, $versions);
        self::assertSame($first->id(), $versions[0]->id());
        self::assertSame('You triage leads.', $versions[0]->systemPrompt());
        self::assertSame('Rewritten.', $versions[1]->systemPrompt());
    }

    // AC-002 seed ----------------------------------------------------------

    public function test_prompt_change_does_not_widen_allowed_tools(): void
    {
        $registry = $this->registry();
        $id = $this->createAgent($registry);

        self::assertSame(['crm.read', 'crm.write'], $registry->allowedTools($id));

        $registry->updatePrompt($id, 'Rewritten.');

        self::assertSame(['crm.read', 'crm.write'], $registry->allowedTools($id));
    }

    public function test_allowed_tools_are_read_only_per_version(): void
    {
        $registry = $this->registry();
        $id = $this->createAgent($registry);

        $version = $registry->activeVersion($id);
        self::assertNotNull($version);

        $tools = $version->allowedTools();
        $tools[] = 'shell.exec';

        // The accessor hands back a copy, so mutating it cannot widen the
        // version's own allow-list (AC-002 starts here, P1-T8 enforces it).
        $reread = $registry->activeVersion($id);
        self::assertNotNull($reread);
        self::assertSame(['crm.read', 'crm.write'], $reread->allowedTools());
    }

    // FR-AGENT-003 — evaluation gates activation -------------------------

    private function passingEval(): \App\Eval\EvalResult
    {
        return \App\Eval\EvalResult::build(true, 3, [[
            'kpi' => 'task_success', 'measured' => 1.0, 'limit' => 0.9,
            'direction' => 'min', 'passed' => true, 'label' => 'task success',
        ]]);
    }

    private function failingEval(): \App\Eval\EvalResult
    {
        return \App\Eval\EvalResult::build(false, 3, [[
            'kpi' => 'task_success', 'measured' => 0.5, 'limit' => 0.9,
            'direction' => 'min', 'passed' => false, 'label' => 'task success',
        ]]);
    }

    public function test_evaluation_passed_records_run_and_activates(): void
    {
        $registry = $this->registry();
        $id = $this->createAgent($registry);
        $version = $registry->latestVersion($id);
        self::assertNotNull($version);

        $gate = new \App\Agents\EvaluationReleaseGate($registry, $registry->evaluations());
        $gate->release($id, $version->id(), $this->passingEval(), ['task_success' => ['limit' => 0.9]]);

        self::assertSame('active', $registry->status($id));

        $eval = $registry->lastEvaluation($id);
        self::assertNotNull($eval);
        self::assertSame(1, (int) $eval['passed']);
        self::assertSame(3, (int) $eval['cases_run']);
    }

    public function test_evaluation_failed_records_run_and_blocks_activation(): void
    {
        $registry = $this->registry();
        $id = $this->createAgent($registry);
        $version = $registry->latestVersion($id);
        self::assertNotNull($version);

        $gate = new \App\Agents\EvaluationReleaseGate($registry, $registry->evaluations());

        try {
            $gate->release($id, $version->id(), $this->failingEval(), ['task_success' => ['limit' => 0.9]]);
            self::fail('A failing evaluation must refuse activation.');
        } catch (\App\Agents\ReleaseGateNotMet $e) {
            self::assertStringContainsString('gate', strtolower($e->getMessage()));
        }

        // The failure is recorded (audit trail) AND the agent stays disabled.
        self::assertSame('disabled', $registry->status($id));
        $eval = $registry->lastEvaluation($id);
        self::assertNotNull($eval);
        self::assertSame(0, (int) $eval['passed']);
        self::assertSame('task_success', $eval['failed_kpis']);
    }

    // AC-001 ---------------------------------------------------------------

    public function test_registry_cannot_be_built_without_a_tenant(): void
    {
        $this->expectException(UnscopedQueryException::class);

        new AgentRegistry($this->pdo, null);
    }

    public function test_agents_and_versions_are_tenant_scoped(): void
    {
        $this->seedOtherTenant();

        $mine = $this->registry();
        $id = $this->createAgent($mine);
        $mine->activate($id, gatesPassed: true);

        $theirs = $this->registry(self::OTHER_TENANT);

        self::assertNull($theirs->find($id));
        self::assertNull($theirs->activeVersion($id));
        self::assertNull($theirs->latestVersion($id));
        self::assertSame([], $theirs->versions($id));
        self::assertSame([], $theirs->allowedTools($id));
    }

    public function test_cross_tenant_write_is_refused(): void
    {
        $this->seedOtherTenant();

        $id = $this->createAgent($this->registry());
        $theirs = $this->registry(self::OTHER_TENANT);

        $this->expectException(UnknownAgent::class);
        $theirs->activate($id, gatesPassed: true);
    }

    public function test_scoping_is_structural_not_conventional(): void
    {
        $agents = new AgentRepository($this->pdo, 1);
        $versions = new AgentVersionRepository($this->pdo, 1);

        self::assertInstanceOf(TenantRepository::class, $agents);
        self::assertInstanceOf(TenantRepository::class, $versions);

        // The generated SQL carries the predicate itself, so an empty result
        // is not the only evidence of scoping (FR-TEN-002).
        self::assertStringContainsString(TenantScope::COLUMN . ' = :' . TenantScope::PARAM, $agents->listSql());
        self::assertStringContainsString(
            TenantScope::COLUMN . ' = :' . TenantScope::PARAM,
            $versions->listSql()
        );
    }
}
