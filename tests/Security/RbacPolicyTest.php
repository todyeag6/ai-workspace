<?php

declare(strict_types=1);

namespace App\Tests\Security;

use App\Security\RbacPolicy;
use App\Security\Subject;
use App\Security\TenantResource;
use App\Tests\TestCase;
use RuntimeException;

/**
 * SEC-005: role-based authorisation is DENY BY DEFAULT.
 *
 * The policy answers a single question - does this subject hold a role that
 * carries this permission code, inside its own tenant - and every other input
 * (unknown action, no roles at all, a role granted in another tenant) has to
 * produce false rather than an exception or a permissive default.
 *
 * © AI WebScapes 2026
 */
final class RbacPolicyTest extends TestCase
{
    private const TENANT = 1;

    public function test_denies_by_default_when_the_subject_holds_no_roles(): void
    {
        $subject = $this->subject($this->seedUser());

        self::assertFalse($this->policy()->permits($subject, 'contact.manage'));
    }

    public function test_denies_an_unknown_action(): void
    {
        $subject = $this->subject($this->seedUser('staff'));

        self::assertFalse(
            $this->policy()->permits($subject, 'no.such.permission'),
            'an action nobody defined must not be permitted'
        );
    }

    public function test_permits_a_granted_action(): void
    {
        $subject = $this->subject($this->seedUser('staff'));

        self::assertTrue($this->policy()->permits($subject, 'lead.read'), 'staff carries lead.read');
        self::assertTrue($this->policy()->permits($subject, 'contact.manage'));
    }

    public function test_denies_an_action_the_role_does_not_carry(): void
    {
        $subject = $this->subject($this->seedUser('viewer'));

        self::assertTrue($this->policy()->permits($subject, 'user.view'), 'viewer carries user.view');
        self::assertFalse($this->policy()->permits($subject, 'contact.manage'), 'viewer must stay read-only');
    }

    public function test_denies_an_object_owned_by_another_tenant(): void
    {
        $subject = $this->subject($this->seedUser('staff'));
        $foreign = new TenantResource('client_contact', '7', self::TENANT + 1);

        self::assertFalse(
            $this->policy()->permits($subject, 'contact.manage', $foreign),
            'AC-001: a permission never reaches across the tenant boundary'
        );
    }

    private function policy(): RbacPolicy
    {
        return new RbacPolicy($this->pdo);
    }

    private function subject(int $userId): Subject
    {
        return new Subject(self::TENANT, $userId, 'test-session', 'test-csrf', false);
    }

    private function seedUser(?string $roleCode = null): int
    {
        $insert = $this->pdo->prepare(
            'INSERT INTO users (tenant_id, email, password_hash, role, is_active, status)'
            . ' VALUES (:tenant_id, :email, :password_hash, :role, 1, :status)'
        );
        if ($insert === false) {
            throw new RuntimeException('Unable to prepare the user fixture insert.');
        }

        $insert->execute([
            'tenant_id' => self::TENANT,
            'email' => 'p1t4-rbac-' . bin2hex(random_bytes(6)) . '@example.test',
            'password_hash' => 'not-used-by-authorisation',
            'role' => 'viewer',
            'status' => 'active',
        ]);
        $userId = (int) $this->pdo->lastInsertId();

        if ($roleCode === null) {
            return $userId;
        }

        $roles = $this->pdo->prepare('SELECT id FROM roles WHERE tenant_id = :tenant_id AND code = :code');
        if ($roles === false) {
            throw new RuntimeException('Unable to prepare the role lookup.');
        }

        $roles->execute(['tenant_id' => self::TENANT, 'code' => $roleCode]);
        $roleId = $roles->fetchColumn();
        if (!is_scalar($roleId)) {
            throw new RuntimeException(sprintf('Role "%s" is not seeded.', $roleCode));
        }

        $grant = $this->pdo->prepare(
            'INSERT INTO user_roles (tenant_id, user_id, role_id) VALUES (:tenant_id, :user_id, :role_id)'
        );
        if ($grant === false) {
            throw new RuntimeException('Unable to prepare the role grant.');
        }

        $grant->execute(['tenant_id' => self::TENANT, 'user_id' => $userId, 'role_id' => (int) $roleId]);

        return $userId;
    }
}
