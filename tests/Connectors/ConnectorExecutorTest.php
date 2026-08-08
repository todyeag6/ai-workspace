<?php

declare(strict_types=1);

namespace App\Tests\Connectors;

use App\AI\ActionAuthority;
use App\Connectors\ConnectorExecutor;
use App\Connectors\ConnectorRegistry;
use App\Connectors\ConnectorSpec;
use App\Connectors\CrmConnectorClient;
use App\Connectors\EmailConnectorClient;
use App\Connectors\HttpConnectorClient;
use App\Tests\TestCase;
use App\Tools\ToolGateway;

/**
 * P2-T2 connector SDK (the actor half of the P1-T8 gateway).
 *
 * These tests prove the executable path end to end WITHOUT a network: every
 * client is built with an injected transport closure, so we assert what each
 * client sends and what it returns. The regression value is in
 * test_executor_refuses_without_gateway_decision and
 * test_unknown_connector_type_has_no_silent_default - the actor must never
 * act on an unauthorised or unbound tool.
 *
 * © AI WebScapes 2026
 */
final class ConnectorExecutorTest extends TestCase
{
    private function gateway(): ToolGateway
    {
        // The lead agent (seeded in migration 003) is granted crm_lookup and
        // send_email; the gate will allow those and refuse anything else.
        return new ToolGateway(
            allowed: ['crm_lookup', 'send_email', 'http_fetch'],
            agent: 'lead',
            agentVersion: 'v1',
            auth: new ActionAuthority(),
            egressAllowlist: ['ops@aiwebscapes.test', '@aiwebscapes.test', '.aiwebscapes.test']
        );
    }

    private function executor(): ConnectorExecutor
    {
        $registry = new ConnectorRegistry($this->pdo);

        $http = new HttpConnectorClient(function (string $method, string $url, array $body) {
            return ['status' => 'ok', 'payload' => ['method' => $method, 'url' => $url, 'body' => $body]];
        });
        $crm = new CrmConnectorClient(function (string $method, string $url, array $body) {
            return ['status' => 'ok', 'payload' => ['url' => $url]];
        });
        $email = new EmailConnectorClient(function (string $method, string $url, array $body) {
            return ['status' => 'sent', 'payload' => $body];
        });

        return new ConnectorExecutor($registry, [$http, $crm, $email]);
    }

    public function test_registry_resolves_tool_to_vetted_connector(): void
    {
        $registry = new ConnectorRegistry($this->pdo);
        $spec = $registry->resolve('crm_lookup');

        self::assertInstanceOf(ConnectorSpec::class, $spec);
        self::assertSame('crm', $spec->type);
        self::assertSame('hubspot', $spec->name);
    }

    public function test_crm_lookup_executes_through_crm_client(): void
    {
        $gateway = $this->gateway();
        $decision = $gateway->invoke('crm_lookup', 'lead', ['object' => 'contact', 'email' => 'jane@aiwebscapes.test']);

        $result = $this->executor()->run($decision);

        self::assertSame('ok', $result['status']);
        self::assertStringContainsString('/crm/v3/objects/contact/', (string) ($result['payload']['url'] ?? ''));
        self::assertSame('hubspot', $result['connector']);
    }

    public function test_send_email_executes_through_email_client(): void
    {
        $gateway = $this->gateway();
        $decision = $gateway->invoke('send_email', 'lead', [
            'to' => 'ops@aiwebscapes.test',
            'subject' => 'Welcome',
            'body' => 'Hello',
        ]);

        $result = $this->executor()->run($decision);

        self::assertSame('sent', $result['status']);
        self::assertSame('ops@aiwebscapes.test', $result['payload']['to']);
    }

    public function test_executor_refuses_without_gateway_decision(): void
    {
        // A decision that was NOT 'allowed' must never be executed.
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('did not allow');

        $this->executor()->run([
            'tool' => 'crm_lookup',
            'agent' => 'lead',
            'agent_version' => 'v1',
            'status' => 'denied',
            'params' => [],
        ]);
    }

    public function test_unknown_connector_type_has_no_silent_default(): void
    {
        // Register only an HTTP client, then ask for a crm tool - there must be
        // no fallback that would swallow the gap.
        $registry = new ConnectorRegistry($this->pdo);
        $executor = new ConnectorExecutor($registry, [
            new HttpConnectorClient(fn () => ['status' => 'ok', 'payload' => null]),
        ]);

        $gateway = $this->gateway();
        $decision = $gateway->invoke('crm_lookup', 'lead', ['object' => 'contact', 'email' => 'jane@aiwebscapes.test']);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('No connector client handles type "crm"');

        $executor->run($decision);
    }

    public function test_gateway_still_refuses_unlisted_tool_before_execution(): void
    {
        $gateway = $this->gateway();
        $this->expectException(\App\Tools\ToolNotAllowed::class);

        // 'refund' is not in this agent's allowlist; the gate refuses, so the
        // executor is never reached. Proves the decider still guards the actor.
        $gateway->invoke('refund', 'lead', ['amount' => 100]);
    }
}
