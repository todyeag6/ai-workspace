<?php

declare(strict_types=1);

namespace App\Tests\Identity;

use App\Tests\TestCase;
use PDO;
use RuntimeException;

/**
 * P1-T1: proves the tenant + identity schema (FR-TEN-001, FR-IDENT-*).
 *
 * Every assertion reads information_schema on the live test database, so it
 * describes the schema that migrations actually produced rather than the SQL
 * text someone intended to write.
 *
 * The headline guard is FR-TEN-001: `users` must be unique on
 * (tenant_id, email) and must NOT carry the legacy email-only UNIQUE key.
 * The legacy key silently makes the platform single-tenant - two tenants
 * could never onboard the same person - so its absence is a regression test,
 * not a nicety.
 *
 * ISOLATION: no test here issues DDL. The base TestCase opens a transaction
 * per test and throws in tearDown() if DDL implicitly committed it away, so
 * this class restricts itself to information_schema SELECTs.
 */
final class SchemaTest extends TestCase
{
    /**
     * Every table the identity domain owns (Platform FRD Table 3).
     */
    private const IDENTITY_TABLES = [
        'tenants',
        'users',
        'roles',
        'permissions',
        'user_roles',
        'client_contacts',
    ];

    /**
     * Tables holding client-owned rows: each MUST be tenant-scoped by a
     * NOT NULL tenant_id so no query can accidentally cross a tenant boundary.
     *
     * `tenants` is excluded because it IS the tenant (its own id is the
     * scope), and `permissions` is excluded because it is a global capability
     * catalogue keyed by `code` - permissions are defined by the platform,
     * granted per tenant through `user_roles`.
     */
    private const TENANT_SCOPED_TABLES = [
        'users',
        'roles',
        'user_roles',
        'client_contacts',
    ];

    /**
     * Runs a single-value information_schema query.
     *
     * $this->pdo uses ERRMODE_EXCEPTION, so the false checks exist to satisfy
     * static analysis and to fail loudly if that attribute is ever relaxed.
     * They throw rather than assert so they never inflate the assertion count.
     *
     * @param array<string, string> $params
     */
    private function scalar(string $sql, array $params): mixed
    {
        $statement = $this->pdo->prepare($sql);
        if ($statement === false) {
            throw new RuntimeException(sprintf('Unable to prepare: %s', $sql));
        }

        $statement->execute($params);

        return $statement->fetchColumn();
    }

    private function tableExists(string $table): bool
    {
        $count = $this->scalar(
            'SELECT COUNT(*) FROM information_schema.TABLES'
            . ' WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :table',
            ['table' => $table]
        );

        return (int) (is_scalar($count) ? $count : 0) > 0;
    }

    /**
     * Returns 'NO' or 'YES' for an existing column, or null when the column
     * does not exist at all - the two failures read very differently.
     */
    private function columnNullability(string $table, string $column): ?string
    {
        $nullable = $this->scalar(
            'SELECT IS_NULLABLE FROM information_schema.COLUMNS'
            . ' WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :table AND COLUMN_NAME = :column',
            ['table' => $table, 'column' => $column]
        );

        return is_string($nullable) ? $nullable : null;
    }

    private function columnType(string $table, string $column): ?string
    {
        $type = $this->scalar(
            'SELECT COLUMN_TYPE FROM information_schema.COLUMNS'
            . ' WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :table AND COLUMN_NAME = :column',
            ['table' => $table, 'column' => $column]
        );

        return is_string($type) ? $type : null;
    }

    /**
     * One comma-separated column signature per UNIQUE index on $table, in
     * SEQ_IN_INDEX order - e.g. ['id', 'tenant_id,email'].
     *
     * Comparing signatures rather than index names keeps the assertions about
     * the actual uniqueness contract instead of someone's naming choice.
     *
     * @return list<string>
     */
    private function uniqueIndexSignatures(string $table): array
    {
        $statement = $this->pdo->prepare(
            'SELECT GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX) AS signature'
            . ' FROM information_schema.STATISTICS'
            . ' WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :table AND NON_UNIQUE = 0'
            . ' GROUP BY INDEX_NAME'
        );
        if ($statement === false) {
            throw new RuntimeException('Unable to prepare the unique-index query.');
        }

        $statement->execute(['table' => $table]);

        $signatures = [];
        foreach ($statement->fetchAll(PDO::FETCH_COLUMN) as $signature) {
            $signatures[] = is_string($signature) ? $signature : '';
        }

        return $signatures;
    }

    public function test_every_identity_table_exists(): void
    {
        foreach (self::IDENTITY_TABLES as $table) {
            self::assertTrue(
                $this->tableExists($table),
                sprintf('Identity table "%s" is missing from the schema.', $table)
            );
        }
    }

    /**
     * FR-TEN-001: the tenant key on `users` is mandatory, never nullable.
     */
    public function test_users_tenant_id_exists_and_is_not_null(): void
    {
        $nullability = $this->columnNullability('users', 'tenant_id');

        self::assertNotNull($nullability, 'users.tenant_id does not exist (FR-TEN-001).');
        self::assertSame('NO', $nullability, 'users.tenant_id must be NOT NULL (FR-TEN-001).');
    }

    /**
     * FR-TEN-001: every client-owned table carries a mandatory tenant scope.
     */
    public function test_every_client_table_has_a_not_null_tenant_id(): void
    {
        foreach (self::TENANT_SCOPED_TABLES as $table) {
            $nullability = $this->columnNullability($table, 'tenant_id');

            self::assertNotNull(
                $nullability,
                sprintf('Client table "%s" has no tenant_id column (FR-TEN-001).', $table)
            );
            self::assertSame(
                'NO',
                $nullability,
                sprintf('%s.tenant_id must be NOT NULL (FR-TEN-001).', $table)
            );
        }
    }

    /**
     * FR-TEN-001: identity is unique per tenant, so the same email address can
     * belong to a different person at a different tenant.
     */
    public function test_users_is_unique_on_tenant_id_and_email(): void
    {
        self::assertContains(
            'tenant_id,email',
            $this->uniqueIndexSignatures('users'),
            'users needs a UNIQUE index on (tenant_id, email) - FR-TEN-001.'
        );
    }

    /**
     * FR-TEN-001 regression guard: the legacy email-only UNIQUE key from
     * 000_baseline.sql breaks multi-tenancy and must have been swapped out.
     */
    public function test_users_has_no_unique_index_on_email_alone(): void
    {
        self::assertNotContains(
            'email',
            $this->uniqueIndexSignatures('users'),
            'The legacy UNIQUE key on users.email alone still exists: two tenants '
            . 'could never share an email address. It must be replaced by '
            . '(tenant_id, email) - FR-TEN-001.'
        );
    }

    /**
     * FR-TEN-001: the tenant scope is referentially enforced, not advisory.
     */
    public function test_users_tenant_id_is_a_foreign_key_to_tenants(): void
    {
        $referenced = $this->scalar(
            'SELECT REFERENCED_TABLE_NAME FROM information_schema.KEY_COLUMN_USAGE'
            . ' WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :table'
            . ' AND COLUMN_NAME = :column AND REFERENCED_TABLE_NAME IS NOT NULL',
            ['table' => 'users', 'column' => 'tenant_id']
        );

        self::assertSame(
            'tenants',
            is_string($referenced) ? $referenced : null,
            'users.tenant_id must be a FOREIGN KEY onto tenants(id) - FR-TEN-001.'
        );
    }

    /**
     * FR-IDENT-001: the schema is MFA-ready from day one.
     */
    public function test_users_is_mfa_ready(): void
    {
        self::assertNotNull(
            $this->columnNullability('users', 'mfa_secret'),
            'users.mfa_secret is required for MFA readiness - FR-IDENT-001.'
        );
    }

    /**
     * FR-IDENT-004: brute-force lockout needs somewhere to count and to wait.
     */
    public function test_users_carries_the_lockout_columns(): void
    {
        foreach (['failed_logins', 'locked_until'] as $column) {
            self::assertNotNull(
                $this->columnNullability('users', $column),
                sprintf('users.%s is required for account lockout - FR-IDENT-004.', $column)
            );
        }

        self::assertSame(
            'NO',
            $this->columnNullability('users', 'failed_logins'),
            'users.failed_logins must be NOT NULL so the counter always has a value.'
        );
        self::assertSame(
            'YES',
            $this->columnNullability('users', 'locked_until'),
            'users.locked_until must be nullable - NULL means "not locked".'
        );
    }

    /**
     * A tenant is addressed by slug in URLs and config, so the slug has to be
     * globally unique.
     */
    public function test_tenants_slug_is_globally_unique(): void
    {
        self::assertContains(
            'slug',
            $this->uniqueIndexSignatures('tenants'),
            'tenants.slug must be UNIQUE - it addresses the tenant.'
        );
    }

    /**
     * Permissions are a global catalogue keyed by a stable code, so authz
     * checks can hard-code the code string.
     */
    public function test_permissions_code_is_unique(): void
    {
        self::assertContains(
            'code',
            $this->uniqueIndexSignatures('permissions'),
            'permissions.code must be UNIQUE - it is the authz lookup key.'
        );
    }

    /**
     * A role assignment is one row per (user, role) within a tenant.
     */
    public function test_user_roles_is_unique_per_tenant_user_and_role(): void
    {
        self::assertContains(
            'tenant_id,user_id,role_id',
            $this->uniqueIndexSignatures('user_roles'),
            'user_roles must be UNIQUE on (tenant_id, user_id, role_id).'
        );
    }

    /**
     * Platform FRD Table 3: the five client contact types the platform must
     * be able to record.
     */
    public function test_client_contacts_covers_every_required_contact_type(): void
    {
        $type = $this->columnType('client_contacts', 'contact_type');

        self::assertNotNull($type, 'client_contacts.contact_type does not exist.');

        foreach (['business', 'technical', 'data', 'billing', 'security'] as $contactType) {
            self::assertStringContainsString(
                sprintf("'%s'", $contactType),
                $type,
                sprintf('client_contacts.contact_type must allow "%s".', $contactType)
            );
        }
    }
}
