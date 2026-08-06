<?php

declare(strict_types=1);

namespace App\Tests\Security;

use App\Audit\AuditLog;
use App\Data\ClientContactLocator;
use App\Identity\SessionStore;
use App\Security\RbacPolicy;
use App\Security\ResourceLocator;
use App\Security\Subject;
use App\Security\TenantAuthMiddleware;
use App\Security\TenantResource;
use App\Tests\TestCase;
use Predis\Client;
use RuntimeException;

/**
 * SEC-005 and AC-001: the authorisation middleware is DENY BY DEFAULT, and a
 * cross-tenant read is impossible through it.
 *
 * THE ENUMERATION PITFALL THIS CLASS PINS DOWN
 * --------------------------------------------
 * The obvious implementation returns 404 for an object that cannot be found
 * and 403 for one the caller may not touch. Applied across tenants that pair
 * is an oracle: tenant A asks for id 7, gets 403 instead of 404, and has just
 * learned that id 7 exists in some other tenant. So both answers must be the
 * SAME answer - 403 with an identical reason - and
 * test_missing_and_cross_tenant_objects_are_indistinguishable() asserts
 * exactly that rather than trusting the two branches to stay aligned.
 *
 * © AI WebScapes 2026
 */
final class TenantAuthMiddlewareTest extends TestCase
{
    private const TENANT = 1;
    private const OTHER_TENANT = 2;
    private const GRANTED_ACTION = 'contact.manage';
    private const UNGRANTED_ACTION = 'tenant.manage';

    private Client $redis;

    /** @var list<string> */
    private array $sessionKeys = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->redis = new Client(['host' => 'redis', 'port' => 6379]);
    }

    protected function tearDown(): void
    {
        foreach ($this->sessionKeys as $key) {
            $this->redis->del([$key]);
        }

        $this->sessionKeys = [];

        parent::tearDown();
    }

    public function test_same_tenant_allowed(): void
    {
        $subject = $this->authenticate($this->seedStaffUser());
        $contactId = $this->seedContact(self::TENANT);

        $result = $this->middleware()->authorise($subject->sessionId(), self::GRANTED_ACTION, $contactId);

        self::assertSame(200, $result->status(), $result->reason());
        self::assertTrue($result->allowed());
        self::assertSame(0, $this->denyCount(), 'an allowed request must not write authz.deny');
    }

    public function test_cross_tenant_read_denied_and_audited(): void
    {
        $subject = $this->authenticate($this->seedStaffUser());
        $foreignContactId = $this->seedContact(self::OTHER_TENANT);

        $result = $this->middleware()->authorise($subject->sessionId(), self::GRANTED_ACTION, $foreignContactId);

        self::assertSame(403, $result->status(), 'AC-001: a cross-tenant object must be refused');
        self::assertNotSame(404, $result->status(), 'a 404 here would be an enumeration oracle');
        self::assertFalse($result->allowed());
        self::assertSame(1, $this->denyCount(), 'FR-AUD-001: the denial must be audited as authz.deny');
    }

    public function test_missing_and_cross_tenant_objects_are_indistinguishable(): void
    {
        $subject = $this->authenticate($this->seedStaffUser());
        $foreignContactId = $this->seedContact(self::OTHER_TENANT);

        $middleware = $this->middleware();
        $foreign = $middleware->authorise($subject->sessionId(), self::GRANTED_ACTION, $foreignContactId);
        $missing = $middleware->authorise($subject->sessionId(), self::GRANTED_ACTION, '999999999');

        self::assertSame($foreign->status(), $missing->status(), 'both must answer 403');
        self::assertSame($foreign->reason(), $missing->reason(), 'the reason must not distinguish them');
        self::assertSame(403, $missing->status());
    }

    public function test_deny_by_default_for_an_ungranted_action(): void
    {
        $subject = $this->authenticate($this->seedStaffUser());
        $contactId = $this->seedContact(self::TENANT);

        $result = $this->middleware()->authorise($subject->sessionId(), self::UNGRANTED_ACTION, $contactId);

        self::assertSame(403, $result->status(), 'SEC-005: nothing is permitted unless a grant says so');
        self::assertSame(1, $this->denyCount());
    }

    public function test_anonymous_request_is_denied(): void
    {
        $result = $this->middleware()->authorise(null, self::GRANTED_ACTION);

        self::assertSame(403, $result->status());
        self::assertNull($result->subject());
    }

    public function test_unknown_session_is_denied(): void
    {
        $result = $this->middleware()->authorise('not-a-real-session-' . bin2hex(random_bytes(4)), 'user.view');

        self::assertSame(403, $result->status(), 'a forged session id must not authenticate anyone');
    }

    public function test_state_changing_request_requires_a_csrf_token(): void
    {
        $subject = $this->authenticate($this->seedStaffUser());
        $contactId = $this->seedContact(self::TENANT);

        $missing = $this->middleware()->authorise(
            $subject->sessionId(),
            self::GRANTED_ACTION,
            $contactId,
            'POST'
        );
        $wrong = $this->middleware()->authorise(
            $subject->sessionId(),
            self::GRANTED_ACTION,
            $contactId,
            'POST',
            'not-the-token'
        );
        $correct = $this->middleware()->authorise(
            $subject->sessionId(),
            self::GRANTED_ACTION,
            $contactId,
            'POST',
            $subject->csrfToken()
        );

        self::assertSame(403, $missing->status(), 'a POST without a CSRF token must be refused');
        self::assertSame(403, $wrong->status(), 'a POST with the wrong CSRF token must be refused');
        self::assertSame(200, $correct->status(), $correct->reason());
    }

    public function test_object_belonging_to_another_tenant_is_refused_even_if_a_locator_returns_it(): void
    {
        $subject = $this->authenticate($this->seedStaffUser());

        // Defence in depth. The real locator cannot return a foreign row - it
        // reads through a tenant-scoped repository - so a hostile stub stands
        // in for a future locator that forgets to scope. The middleware must
        // still refuse rather than trust what it is handed.
        $hostile = new StubResourceLocator(new TenantResource('client_contact', '42', self::OTHER_TENANT));

        $result = $this->middleware($hostile)->authorise($subject->sessionId(), self::GRANTED_ACTION, '42');

        self::assertSame(403, $result->status(), 'the object tenant must be checked, not assumed');
        self::assertSame(1, $this->denyCount());
    }

    private function middleware(?ResourceLocator $locator = null): TenantAuthMiddleware
    {
        return new TenantAuthMiddleware(
            new SessionStore($this->redis, 900),
            new RbacPolicy($this->pdo),
            new AuditLog($this->pdo),
            $locator ?? new ClientContactLocator($this->pdo)
        );
    }

    private function authenticate(int $userId): Subject
    {
        $subject = (new SessionStore($this->redis, 900))->start(self::TENANT, $userId, false);
        $this->sessionKeys[] = SessionStore::KEY_PREFIX . $subject->sessionId();

        return $subject;
    }

    /**
     * Seeds a user holding the seeded 'staff' role (migrations/002), which
     * carries contact.manage and lead.read but NOT tenant.manage.
     */
    private function seedStaffUser(): int
    {
        $insert = $this->prepared(
            'INSERT INTO users (tenant_id, email, password_hash, role, is_active, status)'
            . ' VALUES (:tenant_id, :email, :password_hash, :role, 1, :status)'
        );
        $insert->execute([
            'tenant_id' => self::TENANT,
            'email' => 'p1t4-authz-' . bin2hex(random_bytes(6)) . '@example.test',
            'password_hash' => 'not-used-by-authorisation',
            'role' => 'viewer',
            'status' => 'active',
        ]);
        $userId = (int) $this->pdo->lastInsertId();

        $roles = $this->prepared('SELECT id FROM roles WHERE tenant_id = :tenant_id AND code = :code');
        $roles->execute(['tenant_id' => self::TENANT, 'code' => 'staff']);
        $roleId = $roles->fetchColumn();

        if (!is_scalar($roleId)) {
            throw new RuntimeException("The 'staff' role is missing - migrations/002_authz_audit.sql did not apply.");
        }

        $grant = $this->prepared(
            'INSERT INTO user_roles (tenant_id, user_id, role_id) VALUES (:tenant_id, :user_id, :role_id)'
        );
        $grant->execute(['tenant_id' => self::TENANT, 'user_id' => $userId, 'role_id' => (int) $roleId]);

        return $userId;
    }

    private function seedContact(int $tenantId): string
    {
        if ($tenantId !== self::TENANT) {
            $tenant = $this->prepared(
                'INSERT IGNORE INTO tenants (id, slug, name, status, deployment_model)'
                . ' VALUES (:id, :slug, :name, :status, :deployment_model)'
            );
            $tenant->execute([
                'id' => $tenantId,
                'slug' => 'p1t4-other-' . bin2hex(random_bytes(4)),
                'name' => 'Other Tenant',
                'status' => 'active',
                'deployment_model' => 'cloud',
            ]);
        }

        $contact = $this->prepared(
            'INSERT INTO client_contacts (tenant_id, contact_type, name, email)'
            . ' VALUES (:tenant_id, :contact_type, :name, :email)'
        );
        $contact->execute([
            'tenant_id' => $tenantId,
            'contact_type' => 'business',
            'name' => 'Fixture Contact',
            'email' => 'contact-' . bin2hex(random_bytes(6)) . '@example.test',
        ]);

        return (string) $this->pdo->lastInsertId();
    }

    private function denyCount(): int
    {
        $statement = $this->prepared(
            'SELECT COUNT(*) FROM audit_log WHERE event = :event AND outcome = :outcome'
        );
        $statement->execute(['event' => 'authz.deny', 'outcome' => 'denied']);
        $count = $statement->fetchColumn();

        return is_scalar($count) ? (int) $count : 0;
    }

    private function prepared(string $sql): \PDOStatement
    {
        $statement = $this->pdo->prepare($sql);
        if ($statement === false) {
            throw new RuntimeException(sprintf('Unable to prepare: %s', $sql));
        }

        return $statement;
    }
}
