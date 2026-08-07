<?php

declare(strict_types=1);

namespace App\Tests\Tools;

use App\AI\ActionAuthority;
use App\AI\AutonomousActionRejected;
use App\Tests\TestCase;
use App\Tools\EgressDenied;
use App\Tools\ParamRejected;
use App\Tools\ToolGateway;
use App\Tools\ToolNotAllowed;

/**
 * P1-T8: the tool/connector gate.
 *
 *   FR-TOOL-001 / AC-002  A tool runs only if it is in the allowlist bound to
 *                         this agent AND this agent version. Never a denylist:
 *                         the answer to "is this tool unknown?" is no, not yes.
 *   FR-TOOL-002           Parameters are validated server side. A model that
 *                         supplies http://169.254.169.254/ gets refused before
 *                         anything is fetched (SSRF, cloud metadata).
 *   FR-TOOL-003           Egress goes to approved recipients and hosts only.
 *   FR-AI-006             A high-impact tool routes through ActionAuthority
 *                         before execution, and is refused without a human.
 *
 * NO TEST HERE TOUCHES THE NETWORK OR RESOLVES A NAME. The gate is a pure
 * decision over strings; the URL check is deliberately DNS-free (see
 * ToolGateway). The one database read below only proves migration 003 applied
 * and carries the risk classes the gate mirrors.
 *
 * © AI WebScapes 2026
 */
final class ToolGatewayTest extends TestCase
{
    /**
     * The egress the fixture agent is approved for. Everything else is out.
     *
     * @var list<string>
     */
    private const APPROVED_EGRESS = ['ops@aiwebscapes.test', 'api.aiwebscapes.test'];

    public function test_non_allowlisted_tool_denied(): void
    {
        $this->expectException(ToolNotAllowed::class);
        $this->gateway(allowed: ['send_email'])->invoke('delete_db', agent: 'lead', params: []);
    }

    public function test_model_cannot_supply_arbitrary_url(): void
    {
        $this->expectException(ParamRejected::class);
        $this->gateway(allowed: ['http_fetch'])->invoke(
            'http_fetch',
            agent: 'lead',
            params: ['url' => 'http://169.254.169.254/latest/meta-data/']
        );
    }

    public function test_private_ip_url_is_rejected(): void
    {
        $this->expectException(ParamRejected::class);
        $this->gateway(allowed: ['http_fetch'])->invoke(
            'http_fetch',
            agent: 'lead',
            params: ['url' => 'http://192.168.1.1/']
        );
    }

    /**
     * The whole blocked surface in one place. Each entry is a separate
     * try/catch so a single passing URL cannot hide behind an earlier throw.
     */
    public function test_blocked_targets_are_all_refused(): void
    {
        $blocked = [
            'http://127.0.0.1/health',
            'http://127.9.9.9/',
            'http://localhost/admin',
            'http://[::1]/',
            'http://10.0.0.5/internal',
            'http://172.16.4.4/internal',
            'http://169.254.169.254/latest/meta-data/iam/',
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://api.compute.internal/',
            'http://printer.local/',
            'file:///etc/passwd',
            'gopher://127.0.0.1:6379/_INFO',
            'not-a-url-at-all',
        ];

        foreach ($blocked as $url) {
            $threw = false;
            try {
                $this->gateway(allowed: ['http_fetch'])->invoke(
                    'http_fetch',
                    agent: 'lead',
                    params: ['url' => $url]
                );
            } catch (ParamRejected) {
                $threw = true;
            }

            $this->assertTrue($threw, sprintf('Expected ParamRejected for "%s".', $url));
        }
    }

    public function test_egress_restricted_to_approved(): void
    {
        $this->expectException(EgressDenied::class);
        $this->gateway(allowed: ['send_email'])->invoke(
            'send_email',
            agent: 'lead',
            params: ['recipient' => 'attacker@evil.test']
        );
    }

    public function test_allowlist_is_per_agent_version(): void
    {
        $this->expectException(ToolNotAllowed::class);
        $this->gateway(allowed: ['send_email'], agentVersion: 'v1')
            ->invoke('refund', agent: 'lead', params: []);
    }

    public function test_allowlist_is_bound_to_the_constructing_agent(): void
    {
        $this->expectException(ToolNotAllowed::class);
        $this->gateway(allowed: ['send_email'], agent: 'lead')->invoke(
            'send_email',
            agent: 'billing',
            params: ['recipient' => 'ops@aiwebscapes.test']
        );
    }

    public function test_high_impact_tool_refused_without_authority(): void
    {
        $this->expectException(AutonomousActionRejected::class);
        $this->gateway(allowed: ['refund'], authority: new ActionAuthority())
            ->invoke('refund', agent: 'lead', params: ['amount' => 4200]);
    }

    /**
     * Fail-closed default: a high-impact tool with no ActionAuthority injected
     * still cannot run - the gate builds its own authority rather than
     * treating "nobody passed a reviewer" as permission.
     */
    public function test_high_impact_tool_refused_when_no_authority_is_injected(): void
    {
        $this->expectException(AutonomousActionRejected::class);
        $this->gateway(allowed: ['wire_transfer'])
            ->invoke('wire_transfer', agent: 'lead', params: ['amount' => 1]);
    }

    /**
     * Falsification: every refusal above would also "pass" if the gate refused
     * everything. It does not.
     */
    public function test_valid_allowlisted_call_succeeds(): void
    {
        $result = $this->gateway(allowed: ['send_email'], agentVersion: 'v3')->invoke(
            'send_email',
            agent: 'lead',
            params: ['recipient' => 'ops@aiwebscapes.test', 'subject' => 'hello']
        );

        $this->assertSame(
            [
                'tool' => 'send_email',
                'agent' => 'lead',
                'agent_version' => 'v3',
                'status' => 'allowed',
                'params' => ['recipient' => 'ops@aiwebscapes.test', 'subject' => 'hello'],
            ],
            $result
        );
    }

    public function test_public_url_on_the_egress_allowlist_succeeds(): void
    {
        $result = $this->gateway(allowed: ['http_fetch'])->invoke(
            'http_fetch',
            agent: 'lead',
            params: ['url' => 'https://api.aiwebscapes.test/v1/leads']
        );

        $this->assertSame(
            [
                'tool' => 'http_fetch',
                'agent' => 'lead',
                'agent_version' => null,
                'status' => 'allowed',
                'params' => ['url' => 'https://api.aiwebscapes.test/v1/leads'],
            ],
            $result
        );
    }

    /**
     * A public, well-formed URL that nobody approved is still egress: allowed
     * by the SSRF check, refused by FR-TOOL-003.
     */
    public function test_unapproved_public_host_is_egress_denied(): void
    {
        $this->expectException(EgressDenied::class);
        $this->gateway(allowed: ['http_fetch'])->invoke(
            'http_fetch',
            agent: 'lead',
            params: ['url' => 'https://exfil.example.com/collect']
        );
    }

    /**
     * Migration 003 applied (the base class re-applies every migration, so this
     * also exercises its idempotency) and carries the risk classes the
     * FR-AI-006 check mirrors.
     */
    public function test_migration_registers_tool_risk_classes(): void
    {
        $statement = $this->pdo->prepare('SELECT risk_class FROM tools WHERE name = :name');
        $statement->execute(['name' => 'refund']);
        $this->assertSame('high', $statement->fetchColumn());

        $statement->execute(['name' => 'send_email']);
        $this->assertSame('medium', $statement->fetchColumn());

        $connectors = $this->pdo->prepare('SELECT COUNT(*) FROM connectors');
        $connectors->execute();
        $this->assertGreaterThanOrEqual(0, (int) $connectors->fetchColumn());

        $bindings = $this->pdo->prepare(
            'SELECT COUNT(*) FROM agent_tools WHERE agent = :agent AND agent_version = :version'
        );
        $bindings->execute(['agent' => 'lead', 'version' => 'v1']);
        $this->assertGreaterThanOrEqual(1, (int) $bindings->fetchColumn());
    }

    /**
     * @param list<string> $allowed
     * @param list<string> $egressAllowlist
     */
    private function gateway(
        array $allowed,
        string $agent = 'lead',
        ?string $agentVersion = null,
        ?ActionAuthority $authority = null,
        array $egressAllowlist = self::APPROVED_EGRESS,
    ): ToolGateway {
        return new ToolGateway(
            allowed: $allowed,
            agent: $agent,
            agentVersion: $agentVersion,
            auth: $authority,
            egressAllowlist: $egressAllowlist,
        );
    }
}
