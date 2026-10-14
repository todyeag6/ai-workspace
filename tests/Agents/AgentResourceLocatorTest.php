<?php

declare(strict_types=1);

namespace App\Tests\Agents;

use App\Agents\AgentResourceLocator;
use App\Agents\AgentRegistry;
use App\Security\Subject;
use App\Security\TenantOwned;
use App\Tests\TestCase;
use RuntimeException;

/**
 * AC-001 for the agent console: an agent id resolves ONLY inside its own
 * tenant, and "does not exist" is indistinguishable from "belongs to someone
 * else".
 *
 * WHY THE INDISTINGUISHABILITY ASSERTION IS THE IMPORTANT ONE. The other two
 * tests prove the locator works. This one proves it does not LEAK: if a caller
 * could tell "no such row" apart from "not yours" - by a different return, a
 * different exception, anything - then the id space of every other tenant
 * becomes enumerable one probe at a time. TenantAuthMiddleware maps null to a
 * single 403 for exactly this reason, and that mapping is only sound if the
 * locator genuinely collapses the two cases before it gets there.
 *
 * © AI WebScapes 2026
 */
final class AgentResourceLocatorTest extends TestCase
{
    private const TENANT = 1;

    public function test_locates_an_agent_inside_the_subject_tenant(): void
    {
        $agentId = $this->seedAgent(self::TENANT, 'locator-in-scope');

        $located = $this->locator(self::TENANT)->locate($this->subject(self::TENANT), (string) $agentId);

        self::assertInstanceOf(TenantOwned::class, $located);
        self::assertSame(
            self::TENANT,
            $located->tenantId(),
            'the located object must report the tenant that owns it'
        );
    }

    public function test_returns_null_for_an_agent_owned_by_another_tenant(): void
    {
        $foreignAgentId = $this->seedAgent(self::TENANT + 1, 'locator-foreign');

        self::assertNull(
            $this->locator(self::TENANT)->locate($this->subject(self::TENANT), (string) $foreignAgentId),
            'AC-001: a foreign tenant\'s agent must not resolve'
        );
    }

    public function test_returns_null_for_an_agent_that_does_not_exist(): void
    {
        self::assertNull(
            $this->locator(self::TENANT)->locate($this->subject(self::TENANT), '999999999'),
            'an unknown id must not resolve'
        );
    }

    /**
     * The enumeration-oracle guard. Both negative paths must produce the SAME
     * observable outcome, so a probe cannot tell them apart.
     */
    public function test_a_foreign_agent_and_a_missing_agent_are_indistinguishable(): void
    {
        $foreignAgentId = $this->seedAgent(self::TENANT + 1, 'locator-oracle');
        $locator = $this->locator(self::TENANT);
        $subject = $this->subject(self::TENANT);

        $foreign = $locator->locate($subject, (string) $foreignAgentId);
        $missing = $locator->locate($subject, '999999999');

        self::assertNull($foreign);
        self::assertNull($missing);
        self::assertSame(
            $foreign,
            $missing,
            'AC-001: "not yours" and "does not exist" must be one answer'
        );
    }

    /**
     * A non-numeric id must not be coerced to 0 and looked up. Casting junk to
     * an int is how a locator accidentally resolves row 0 or trips a type
     * error mid-authorization; returning null keeps the failure inside the
     * "unavailable" answer the middleware already handles.
     */
    public function test_rejects_a_non_numeric_object_id_without_looking_it_up(): void
    {
        $locator = $this->locator(self::TENANT);

        self::assertNull($locator->locate($this->subject(self::TENANT), 'not-a-number'));
        self::assertNull($locator->locate($this->subject(self::TENANT), ''));
        self::assertNull($locator->locate($this->subject(self::TENANT), '12abc'));
    }

    private function locator(int $tenantId): AgentResourceLocator
    {
        // $tenantId is still used to build the Subject; the locator itself
        // takes its scope from the subject on every call (see the class
        // docblock — PHPStan L8 rejected a constructor tenant as never-read).
        return new AgentResourceLocator($this->pdo);
    }

    private function subject(int $tenantId): Subject
    {
        return new Subject($tenantId, 1, 'test-session', 'test-csrf', false);
    }

    /**
     * Seeds a tenant and an agent directly. Deliberately not through
     * AgentRegistry: this test is about the locator's scoping, and routing the
     * fixture through the registry would make a registry bug look like a
     * locator bug.
     */
    private function seedAgent(int $tenantId, string $name): int
    {
        $tenant = $this->pdo->prepare(
            'INSERT IGNORE INTO tenants (id, slug, name, status, deployment_model)'
            . ' VALUES (:id, :slug, :name, :status, :model)'
        );
        if ($tenant === false) {
            throw new RuntimeException('Unable to prepare the tenant fixture.');
        }
        $tenant->execute([
            'id' => $tenantId,
            'slug' => 'locator-tenant-' . $tenantId,
            'name' => 'Locator Tenant ' . $tenantId,
            'status' => 'active',
            'model' => 'cloud',
        ]);

        $insert = $this->pdo->prepare(
            'INSERT INTO agents (tenant_id, name, owner, purpose, risk_class, status)'
            . ' VALUES (:tenant_id, :name, :owner, :purpose, :risk, :status)'
        );
        if ($insert === false) {
            throw new RuntimeException('Unable to prepare the agent fixture.');
        }
        $insert->execute([
            'tenant_id' => $tenantId,
            'name' => $name . '-' . bin2hex(random_bytes(4)),
            'owner' => 'test-owner',
            'purpose' => 'locator test',
            'risk' => 'low',
            'status' => AgentRegistry::STATUS_DISABLED,
        ]);

        return (int) $this->pdo->lastInsertId();
    }
}
