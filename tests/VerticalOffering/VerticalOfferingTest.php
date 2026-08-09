<?php

declare(strict_types=1);

namespace App\Tests\VerticalOffering;

use App\Agents\AgentEvaluationRepository;
use App\Agents\AgentRegistry;
use App\Agents\EvaluationReleaseGate;
use App\Eval\EvalResult;
use App\ManagedOps\AgentOwnershipRepository;
use App\ManagedOps\SlaRepository;
use App\Tests\TestCase;
use App\VerticalOffering\LaunchedOfferingRepository;
use App\VerticalOffering\VertalTemplateLoadFailure;
use App\VerticalOffering\VerticalLauncher;
use App\VerticalOffering\VerticalTemplate;
use InvalidArgumentException;
use PDO;
use RuntimeException;

/**
 * P2-T5 — Packaged vertical offering (one templated repeatable engagement).
 *
 * A vertical package composes the already-built modules (AgentRegistry's
 * disabled-by-default registration, EvaluationReleaseGate's eval-gated
 * activation, AgentOwnershipRepository's append-only accountability,
 * SlaRepository's SLA targets, WorkflowBuilder's launch-workflow validation)
 * into a single named, repeatable offering. The launcher must NOT reintroduce
 * any authz/activation primitive — it reuses them.
 *
 * Faithful constraints asserted here:
 *  - activation is gated by the evaluation verdict (FR-AGENT-003); a failing
 *    verdict leaves every agent DISABLED (fail-closed), though the blueprint
 *    (ownership + SLA targets + launched record) is still recorded;
 *  - the launch workflow is validated BEFORE any agent is written, so a bad
 *    template cannot half-launch (fail-closed on WorkflowBuilder);
 *  - a template with an unknown ownership role / SLA type / empty agent list
 *    is refused at load;
 *  - everything is tenant-scoped (AC-001): a tenant B launcher sees none of
 *    tenant A's agents, ownership, SLA or launched rows.
 *
 * © AI WebScapes 2026
 */
final class VerticalOfferingTest extends TestCase
{
    private function registry(PDO $pdo, int $tenant): AgentRegistry
    {
        return new AgentRegistry($pdo, $tenant);
    }

    private function launcher(PDO $pdo, int $tenant): VerticalLauncher
    {
        return new VerticalLauncher(
            new AgentRegistry($pdo, $tenant),
            new AgentEvaluationRepository($pdo, $tenant),
            new AgentOwnershipRepository($pdo, $tenant),
            new SlaRepository($pdo, $tenant),
            new LaunchedOfferingRepository($pdo, $tenant)
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function agent(string $key, string $name): array
    {
        return [
            'key' => $key,
            'name' => $name,
            'owner' => 'platform-ops',
            'purpose' => 'Follow up on inbound leads.',
            'system_prompt' => 'You analyse leads.',
            'risk_class' => 'high',
            'allowed_tools' => ['crm_write', 'email_send'],
            'data_classes' => ['contact', 'company'],
            'deployment_location' => 'cloud',
            'ownership' => [
                'business_owner' => 'biz@example.com',
                'technical_owner' => 'eng@example.com',
                'data_owner' => 'dpo@example.com',
                'security_owner' => 'sec@example.com',
                'acceptance_authority' => 'accept@example.com',
                'update_owner' => 'update@example.com',
                'backup_owner' => 'backup@example.com',
            ],
            'sla_targets' => [
                ['type' => 'patch', 'target_hours' => 72.0],
                ['type' => 'incident_response', 'target_hours' => 4.0],
                ['type' => 'backup_restore_test', 'target_hours' => 168.0],
            ],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function templateArray(): array
    {
        return [
            'name' => 'Lead Follow-Up MVP',
            'description' => 'Bundled lead follow-up engagement.',
            'purpose' => 'lead',
            'support' => [
                'tier' => 'standard',
                'boundary' => 'Client owns end-user data entry.',
                'contacts' => [
                    ['role' => 'primary', 'channel' => 'email', 'target' => 'support@example.com'],
                ],
            ],
            'agents' => [
                $this->agent('analyst', 'Lead Analyst'),
                $this->agent('router', 'Lead Router'),
            ],
            'launch_workflow' => [
                'workflow_id' => 'lead_followup_launch',
                'steps' => [
                    ['type' => 'charge', 'risk' => 'low'],
                    ['type' => 'reserve_stock', 'risk' => 'medium'],
                ],
            ],
        ];
    }

    private function passingEval(): EvalResult
    {
        return EvalResult::build(true, 1, [[
            'kpi' => 'task_success',
            'measured' => 1.0,
            'limit' => 0.9,
            'direction' => 'min',
            'passed' => true,
            'label' => 'Task success',
        ]]);
    }

    private function failingEval(): EvalResult
    {
        return EvalResult::build(false, 1, [[
            'kpi' => 'task_success',
            'measured' => 0.5,
            'limit' => 0.9,
            'direction' => 'min',
            'passed' => false,
            'label' => 'Task success',
        ]]);
    }

    public function test_template_rejects_unknown_ownership_role(): void
    {
        $t = $this->templateArray();
        $t['agents'][0]['ownership']['not_a_role'] = 'x';

        $this->expectException(InvalidArgumentException::class);
        VerticalTemplate::fromArray($t);
    }

    public function test_template_rejects_unknown_sla_type(): void
    {
        $t = $this->templateArray();
        $t['agents'][0]['sla_targets'][0]['type'] = 'lateness';

        $this->expectException(InvalidArgumentException::class);
        VerticalTemplate::fromArray($t);
    }

    public function test_template_rejects_empty_agents(): void
    {
        $t = $this->templateArray();
        $t['agents'] = [];

        $this->expectException(InvalidArgumentException::class);
        VerticalTemplate::fromArray($t);
    }

    public function test_template_rejects_unknown_support_tier(): void
    {
        $t = $this->templateArray();
        $t['support']['tier'] = 'platinum';

        $this->expectException(InvalidArgumentException::class);
        VerticalTemplate::fromArray($t);
    }

    public function test_launcher_registers_multi_agent_blueprint_and_activates_when_eval_passes(): void
    {
        $template = VerticalTemplate::fromArray($this->templateArray());
        $launch = $this->launcher($this->pdo, 1)->launch($template, $this->passingEval(), 'launch-owner');

        self::assertTrue($launch->activated, 'A passing eval must activate the offering.');
        self::assertCount(2, $launch->agentIds, 'Both bundled agents must be registered.');
        self::assertSame('Lead Follow-Up MVP', $launch->templateName);

        $registry = $this->registry($this->pdo, 1);
        foreach ($launch->agentIds as $agentId) {
            self::assertSame(AgentRegistry::STATUS_ACTIVE, $registry->status($agentId), 'Activated agent must be active.');
        }

        // Ownership + SLA blueprint recorded for every agent.
        $ownership = new AgentOwnershipRepository($this->pdo, 1);
        $slas = new SlaRepository($this->pdo, 1);
        foreach ($launch->agentIds as $agentId) {
            self::assertNotNull($ownership->current($agentId), 'Ownership roster must be recorded.');
            self::assertCount(3, $slas->forAgent($agentId), 'Three SLA targets must be recorded.');
        }

        // Launched record exists and is marked activated.
        $launched = new LaunchedOfferingRepository($this->pdo, 1);
        $row = $launched->find($launch->templateName);
        self::assertNotNull($row);
        self::assertSame(1, (int) $row['activated']);
    }

    public function test_launcher_fails_closed_when_eval_does_not_pass(): void
    {
        $template = VerticalTemplate::fromArray($this->templateArray());
        $launch = $this->launcher($this->pdo, 1)->launch($template, $this->failingEval(), 'launch-owner');

        self::assertFalse($launch->activated, 'A failing eval must NOT activate the offering.');
        self::assertContains('task_success', $launch->failedKpis);
        self::assertCount(2, $launch->agentIds);

        // Agents exist (blueprint) but stay DISABLED — the gate refused them.
        $registry = $this->registry($this->pdo, 1);
        foreach ($launch->agentIds as $agentId) {
            self::assertSame(AgentRegistry::STATUS_DISABLED, $registry->status($agentId));
        }

        // Blueprint still recorded so the failure is auditable.
        $ownership = new AgentOwnershipRepository($this->pdo, 1);
        foreach ($launch->agentIds as $agentId) {
            self::assertNotNull($ownership->current($agentId));
        }
        $row = (new LaunchedOfferingRepository($this->pdo, 1))->find($launch->templateName);
        self::assertNotNull($row);
        self::assertSame(0, (int) $row['activated']);
    }

    public function test_launcher_validates_workflow_before_writing_any_agent(): void
    {
        $t = $this->templateArray();
        // An unexecutable step type must be refused at authoring, and the
        // launcher must not have created a single agent by the time it throws.
        $t['launch_workflow']['steps'] = [['type' => 'nuke', 'risk' => 'low']];

        $launcher = $this->launcher($this->pdo, 1);
        $this->expectException(InvalidArgumentException::class);
        $launcher->launch(VerticalTemplate::fromArray($t), $this->passingEval(), 'launch-owner');

        // No launched record was written for the doomed offering.
        self::assertNull((new LaunchedOfferingRepository($this->pdo, 1))->find('Lead Follow-Up MVP'));
    }

    public function test_launched_offering_is_tenant_scoped(): void
    {
        $template = VerticalTemplate::fromArray($this->templateArray());
        $this->launcher($this->pdo, 1)->launch($template, $this->passingEval(), 'launch-owner');

        // Tenant 2 sees none of tenant 1's agents, ownership, SLA or launch.
        $registry2 = $this->registry($this->pdo, 2);
        $launched2 = new LaunchedOfferingRepository($this->pdo, 2);
        self::assertNull($launched2->find('Lead Follow-Up MVP'));
        self::assertNull($registry2->find(1));
    }

    public function test_loads_real_lead_followup_template_and_launches(): void
    {
        $template = VerticalTemplate::fromFile(__DIR__ . '/../../config/verticals/LEAD_FOLLOWUP.php');
        self::assertSame('Lead Follow-Up MVP', $template->name());
        self::assertGreaterThanOrEqual(2, count($template->agents()), 'The shipped template must bundle multiple agents.');

        $launch = $this->launcher($this->pdo, 1)->launch($template, $this->passingEval(), 'launch-owner');
        self::assertTrue($launch->activated);
        self::assertCount(count($template->agents()), $launch->agentIds);
    }
}
