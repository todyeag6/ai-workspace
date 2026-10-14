<?php

declare(strict_types=1);

namespace App\Tests\Console;

use App\Agents\AgentRegistry;
use App\Console\AgentConsoleController;
use App\Console\AgentConsoleView;
use App\Tests\TestCase;
use RuntimeException;

/**
 * The console's list endpoint (FR-AGENT-001, AC-001, FR-DASH-001).
 *
 * WHAT THIS PROVES AND WHAT IT DELIBERATELY DOES NOT. The controller's job is
 * narrow: route, ask the registry for the tenant's agents, hand them to the
 * view. It performs no scoping of its own - AgentRegistry::listActive() is
 * already tenant-bound, and AgentRepository extends TenantRepository, so an
 * unscoped read is not expressible. That is exactly why the cross-tenant test
 * below matters: it asserts the guarantee holds END TO END through the
 * controller, rather than trusting that the layer underneath is careful.
 *
 * The rendering guarantees (escaping, landmarks, CSP-safe markup) belong to
 * tests/Console/AgentConsoleViewTest.php and are not repeated here.
 *
 * © AI WebScapes 2026
 */
final class AgentConsoleControllerTest extends TestCase
{
    private const TENANT = 1;

    public function test_get_console_returns_200_with_the_tenants_active_agents(): void
    {
        $name = $this->seedActiveAgent(self::TENANT, 'list-visible');

        $response = $this->controller(self::TENANT)->handle([
            'method' => 'GET',
            'path' => AgentConsoleController::PATH,
        ]);

        self::assertSame(200, $response['status']);
        self::assertIsString($response['body']['html'] ?? null);
        self::assertStringContainsString(
            $name,
            (string) $response['body']['html'],
            'the tenant\'s own active agent must appear'
        );
    }

    /**
     * FR-AGENT-002: an agent that is not active must not be advertised. The
     * registry already filters on status='active'; this asserts the controller
     * does not re-widen the list on its way to the view.
     */
    public function test_a_disabled_agent_is_absent_from_the_list(): void
    {
        $name = $this->seedActiveAgent(self::TENANT, 'list-then-disabled');

        $registry = new AgentRegistry($this->pdo, self::TENANT);
        $agentId = $this->agentIdByName($name);
        $registry->disable($agentId);

        $response = $this->controller(self::TENANT)->handle([
            'method' => 'GET',
            'path' => AgentConsoleController::PATH,
        ]);

        self::assertSame(200, $response['status']);
        self::assertStringNotContainsString(
            $name,
            (string) $response['body']['html'],
            'a disabled agent must not be listed'
        );
    }

    /**
     * AC-001, the load-bearing negative test. A second tenant's active agent
     * must be invisible to this tenant's console - not merely unlinked, but
     * absent from the served bytes.
     */
    public function test_another_tenants_agent_is_absent_from_the_list(): void
    {
        $this->seedTenant(self::TENANT + 1);
        $foreignName = $this->seedActiveAgent(self::TENANT + 1, 'list-foreign');
        $ownName = $this->seedActiveAgent(self::TENANT, 'list-own');

        $response = $this->controller(self::TENANT)->handle([
            'method' => 'GET',
            'path' => AgentConsoleController::PATH,
        ]);

        self::assertSame(200, $response['status']);
        $html = (string) $response['body']['html'];

        self::assertStringContainsString($ownName, $html, 'the tenant\'s own agent must still appear');
        self::assertStringNotContainsString(
            $foreignName,
            $html,
            'AC-001: another tenant\'s agent must not be served'
        );
    }

    public function test_an_empty_registry_returns_200_with_an_empty_state(): void
    {
        $response = $this->controller(self::TENANT)->handle([
            'method' => 'GET',
            'path' => AgentConsoleController::PATH,
        ]);

        self::assertSame(200, $response['status']);
        self::assertStringContainsString('No active agents', (string) $response['body']['html']);
    }

    public function test_an_unsupported_method_returns_405(): void
    {
        $response = $this->controller(self::TENANT)->handle([
            'method' => 'POST',
            'path' => AgentConsoleController::PATH,
        ]);

        self::assertSame(405, $response['status']);
    }

    public function test_an_unknown_path_returns_404(): void
    {
        $response = $this->controller(self::TENANT)->handle([
            'method' => 'GET',
            'path' => '/console/nope',
        ]);

        self::assertSame(404, $response['status']);
    }

    private function controller(int $tenantId): AgentConsoleController
    {
        return new AgentConsoleController(
            new AgentRegistry($this->pdo, $tenantId),
            new AgentConsoleView()
        );
    }

    /**
     * Creates an ACTIVE agent through the registry, so it carries an active
     * version. listActive() skips an agent whose active version is missing, so
     * a fixture inserted straight into the agents table would be filtered out
     * and the test would pass for the wrong reason.
     */
    private function seedActiveAgent(int $tenantId, string $prefix): string
    {
        $this->seedTenant($tenantId);

        $name = $prefix . '-' . bin2hex(random_bytes(4));
        $registry = new AgentRegistry($this->pdo, $tenantId);

        $agentId = $registry->create(
            name: $name,
            owner: 'test-owner',
            purpose: 'console listing test',
            systemPrompt: 'You are a test agent.',
            riskClass: 'low',
            allowedTools: [],
            modelConfig: ['model' => 'test-model'],
        );

        $registry->activate($agentId, true);

        return $name;
    }

    private function seedTenant(int $tenantId): void
    {
        $statement = $this->pdo->prepare(
            'INSERT IGNORE INTO tenants (id, slug, name, status, deployment_model)'
            . ' VALUES (:id, :slug, :name, :status, :model)'
        );
        if ($statement === false) {
            throw new RuntimeException('Unable to prepare the tenant fixture.');
        }

        $statement->execute([
            'id' => $tenantId,
            'slug' => 'console-tenant-' . $tenantId,
            'name' => 'Console Tenant ' . $tenantId,
            'status' => 'active',
            'model' => 'cloud',
        ]);
    }

    private function agentIdByName(string $name): int
    {
        $statement = $this->pdo->prepare('SELECT id FROM agents WHERE name = :name');
        if ($statement === false) {
            throw new RuntimeException('Unable to prepare the agent id lookup.');
        }
        $statement->execute(['name' => $name]);
        $id = $statement->fetchColumn();

        if (!is_scalar($id)) {
            throw new RuntimeException(sprintf('No agent named "%s".', $name));
        }

        return (int) $id;
    }
}
