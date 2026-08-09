<?php

declare(strict_types=1);

namespace App\Tests\SecurityAgent;

use App\Audit\AuditLogger;
use App\SecurityAgent\Authorization;
use App\SecurityAgent\AuthorizationRepository;
use App\SecurityAgent\IncompleteAuthorization;
use App\SecurityAgent\OwnershipUnverified;
use App\SecurityAgent\OwnershipVerifier;
use App\SecurityAgent\ScopedSecretStore;
use App\SecurityAgent\ScopeManager;
use App\SecurityAgent\TargetCanonicalizer;
use App\Tenancy\TenantScope;
use App\Tests\TestCase;
use DateTimeImmutable;
use PDO;

/**
 * P3-T1 — Authorization & Scope Manager (SFR-AUTH-001/002/003, SBR-3.1/3.2).
 *
 * Each test maps to a baseline requirement:
 *
 *  - SFR-AUTH-001 / SBR-3.1: an authorization missing any of active status,
 *    tenant, technique profile, validity period or stop contact cannot
 *    schedule; an expired one cannot start (P3 exit-gate acceptance test
 *    "Expired authorization -> Scan cannot start").
 *  - SFR-AUTH-002: targets are canonicalized and re-checked against scope on
 *    EVERY request, and a denial is RECORDED (P3 exit-gate acceptance test
 *    "Redirect out of scope -> Request stops and event is recorded").
 *  - SFR-AUTH-003: credentials are stored as scoped secrets (ciphertext) and
 *    never appear in a report.
 *  - SBR-3.2: ownership/delegated authority is verified by an approved method
 *    before an authorization can become active.
 *  - AC-001: none of the above is visible across a tenant boundary.
 *
 * © AI WebScapes 2026
 */
final class AuthorizationScopeTest extends TestCase
{
    /** A fixed 32-byte key: APP_KEY is deliberately NOT read at runtime. */
    private const TEST_KEY = 'kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk';

    private const SECRET = 'scan-svc-account-password-9f2b';

    // ---------------------------------------------------------------
    // SFR-AUTH-001 / SBR-3.1 — completeness is a precondition of scheduling
    // ---------------------------------------------------------------

    public function test_cannot_schedule_without_complete_authorization(): void
    {
        $now = new DateTimeImmutable('2026-06-01 12:00:00');

        // Missing validity end: no bounded window means no schedulable window.
        $noValidTo = Authorization::fromRow($this->row(['valid_to' => null]));
        self::assertFalse($noValidTo->canSchedule($now));
        self::assertFalse($noValidTo->isActive($now));

        // Missing stop contact: nobody to call to abort an active test.
        $noContact = Authorization::fromRow($this->row(['stop_contact' => '']));
        self::assertFalse($noContact->canSchedule($now));

        // Missing technique profile: no agreed technique envelope.
        $noProfile = Authorization::fromRow($this->row(['technique_profile' => '[]']));
        self::assertFalse($noProfile->canSchedule($now));

        // A complete, active, in-window authorization CAN schedule.
        self::assertTrue(Authorization::fromRow($this->row())->canSchedule($now));

        // Same guarantee at the request gate: a row that reached 'active'
        // with a NULL validity end (e.g. written around the application) is
        // still refused per-request, not trusted because of its status.
        $this->seedTenant(1);
        $id = $this->insertAuthorization(1, ['status' => 'active', 'valid_to' => null]);
        $repo = $this->repository(1);
        $repo->addTarget($id, 'https://app.acme.test/login');

        $result = $this->scopeManager(1, $repo)->checkRequest($id, 'https://app.acme.test/login', $now);

        self::assertFalse($result['allowed']);
        self::assertSame('authorization_inactive_or_expired', $result['reason']);

        // The repository refuses to activate an incomplete authorization too.
        $this->expectException(IncompleteAuthorization::class);
        $repo->activate($this->createDraft($repo, omitValidTo: true));
    }

    // ---------------------------------------------------------------
    // SBR-3.2 — approved ownership proof before active testing
    // ---------------------------------------------------------------

    public function test_ownership_proof_required_before_active(): void
    {
        $this->seedTenant(1);
        $repo = $this->repository(1);

        $unapproved = $this->createDraft($repo, proofType: 'verbal-ok-on-a-call');
        self::assertFalse((new OwnershipVerifier())->verify($repo->requireById($unapproved)));

        $approved = $this->createDraft($repo);
        self::assertTrue((new OwnershipVerifier())->verify($repo->requireById($approved)));

        // Only the approved proof moves the status to 'active'.
        $repo->activate($approved);
        $active = $repo->requireById($approved);
        self::assertSame('active', $active->status());
        self::assertTrue($active->isActive(new DateTimeImmutable('2026-06-01 12:00:00')));

        // A draft never becomes schedulable by itself.
        self::assertFalse($repo->requireById($unapproved)->canSchedule(new DateTimeImmutable('2026-06-01 12:00:00')));

        $this->expectException(OwnershipUnverified::class);
        $repo->activate($unapproved);
    }

    // ---------------------------------------------------------------
    // P3 exit-gate: "Expired authorization -> Scan cannot start"
    // ---------------------------------------------------------------

    public function test_expired_authorization_blocks_start(): void
    {
        $this->seedTenant(1);
        $repo = $this->repository(1);

        $id = $this->createDraft(
            $repo,
            validFrom: new DateTimeImmutable('2026-01-01 00:00:00'),
            validTo: new DateTimeImmutable('2026-02-01 00:00:00')
        );
        $repo->activate($id);
        $repo->addTarget($id, 'https://app.acme.test/login');

        $now = new DateTimeImmutable('2026-06-01 12:00:00');

        // In-window the very same request is allowed - so the refusal below is
        // caused by expiry and nothing else.
        $inWindow = $this->scopeManager(1, $repo)
            ->checkRequest($id, 'https://app.acme.test/login', new DateTimeImmutable('2026-01-15 09:00:00'));
        self::assertTrue($inWindow['allowed']);

        $result = $this->scopeManager(1, $repo)->checkRequest($id, 'https://app.acme.test/login', $now);

        self::assertFalse($result['allowed']);
        self::assertSame('authorization_inactive_or_expired', $result['reason']);
        self::assertSame(1, $this->denialEvents(1), 'The expired-start refusal must be recorded.');
    }

    // ---------------------------------------------------------------
    // SFR-AUTH-002 + P3 exit-gate: "Redirect out of scope -> Request stops
    // and event is recorded"
    // ---------------------------------------------------------------

    public function test_out_of_scope_request_rejected_and_recorded(): void
    {
        $this->seedTenant(1);
        $repo = $this->repository(1);

        $id = $this->createDraft($repo);
        $repo->activate($id);
        $repo->addTarget($id, 'https://app.acme.test/login');

        $now = new DateTimeImmutable('2026-06-01 12:00:00');
        $manager = $this->scopeManager(1, $repo);

        // The in-scope request the scan started from.
        self::assertTrue($manager->checkRequest($id, 'https://app.acme.test/login', $now)['allowed']);
        self::assertSame(0, $this->denialEvents(1));

        // The redirect target. Re-checked before the request is issued, so the
        // redirect is never followed.
        $result = $manager->checkRequest($id, 'https://tracker.evil.test/collect', $now);

        self::assertFalse($result['allowed']);
        self::assertSame('out_of_scope', $result['reason']);
        self::assertSame(1, $this->denialEvents(1), 'An out-of-scope refusal must be recorded.');
        self::assertSame(
            'https://tracker.evil.test/collect',
            $this->lastDenialObjectId(1),
            'The recorded event names the canonicalized target that was refused.'
        );

        // An explicitly EXCLUDED target is refused even though it is listed.
        $repo->addTarget($id, 'https://admin.acme.test/', excluded: true);
        $excluded = $manager->checkRequest($id, 'https://admin.acme.test/', $now);
        self::assertFalse($excluded['allowed']);
        self::assertSame('out_of_scope', $excluded['reason']);
        self::assertSame(2, $this->denialEvents(1));
    }

    // ---------------------------------------------------------------
    // SFR-AUTH-002 — canonicalization happens BEFORE the scope match
    // ---------------------------------------------------------------

    public function test_targets_canonicalized_before_scope_check(): void
    {
        $this->seedTenant(1);
        $repo = $this->repository(1);

        $id = $this->createDraft($repo);
        $repo->activate($id);
        $repo->addTarget($id, 'https://app.acme.test/login');

        $now = new DateTimeImmutable('2026-06-01 12:00:00');
        $manager = $this->scopeManager(1, $repo);

        // Differs only by scheme case, host case, default port, trailing host
        // dot and a fragment - all of which canonicalization removes.
        $result = $manager->checkRequest($id, 'HTTPS://APP.Acme.TEST.:443/login#section', $now);

        self::assertTrue($result['allowed'], 'A canonically identical target must match the scope entry.');
        self::assertSame('https://app.acme.test/login', $result['target']);
        self::assertSame(0, $this->denialEvents(1));

        // A different host is NOT made in-scope by canonicalization.
        self::assertFalse($manager->checkRequest($id, 'https://app.acme.test.evil.test/login', $now)['allowed']);
    }

    public function test_canonicalizer_is_deterministic_and_pure(): void
    {
        self::assertSame(
            'https://example.com/path/?b=2&a=1',
            TargetCanonicalizer::canonicalize('HTTPS://Example.COM:443/path/?b=2&a=1#frag')
        );

        // Idempotent: canonicalizing a canonical target changes nothing.
        self::assertSame(
            'https://example.com/path/?b=2&a=1',
            TargetCanonicalizer::canonicalize('https://example.com/path/?b=2&a=1')
        );

        self::assertSame('http://example.com/', TargetCanonicalizer::canonicalize('HTTP://example.com:80'));
        self::assertSame('https://example.com:8443/', TargetCanonicalizer::canonicalize('https://example.com:8443'));

        // Percent-encoding is preserved and normalised to uppercase hex.
        self::assertSame('https://example.com/a%2Fb', TargetCanonicalizer::canonicalize('https://example.com/a%2fb'));
    }

    // ---------------------------------------------------------------
    // SFR-AUTH-003 — scoped secret, never in a report
    // ---------------------------------------------------------------

    public function test_credential_stored_encrypted_never_in_report(): void
    {
        $this->seedTenant(1);
        $store = new ScopedSecretStore(self::TEST_KEY);
        $repo = new AuthorizationRepository($this->pdo, 1, $store);

        $id = $this->createDraft($repo, credential: self::SECRET);

        $statement = $this->pdo->prepare(
            'SELECT credentials_ciphertext, credentials_fingerprint FROM security_authorizations'
            . ' WHERE id = :id AND ' . TenantScope::COLUMN . ' = :' . TenantScope::PARAM
        );
        $statement->bindValue('id', $id, PDO::PARAM_INT);
        (new TenantScope(1))->bindTo($statement);
        $statement->execute();
        $row = $statement->fetch(PDO::FETCH_ASSOC);

        self::assertIsArray($row);
        $cipher = (string) $row['credentials_ciphertext'];
        $fingerprint = (string) $row['credentials_fingerprint'];

        self::assertNotSame(self::SECRET, $cipher);
        self::assertStringNotContainsString(self::SECRET, $cipher);
        self::assertSame(self::SECRET, $store->decrypt($cipher), 'The stored secret must round-trip.');
        self::assertSame($store->fingerprint(self::SECRET), $fingerprint);

        // The report view carries the fingerprint and NOTHING else about the
        // credential - not the plaintext, not the ciphertext (SFR-AUTH-003).
        $report = $repo->requireById($id)->toReportArray();
        self::assertArrayHasKey('credentials_fingerprint', $report);
        self::assertSame($fingerprint, $report['credentials_fingerprint']);
        self::assertArrayNotHasKey('credentials_ciphertext', $report);

        $encoded = (string) json_encode($report);
        self::assertStringNotContainsString(self::SECRET, $encoded);
        self::assertStringNotContainsString($cipher, $encoded);

        // Two different secrets fingerprint differently; the same one matches.
        self::assertNotSame($store->fingerprint('other'), $fingerprint);
        self::assertStringStartsWith('sha256:', $fingerprint);
    }

    // ---------------------------------------------------------------
    // AC-001 — nothing crosses the tenant boundary
    // ---------------------------------------------------------------

    public function test_cross_tenant_authorization_invisible(): void
    {
        $this->seedTenant(1);
        $this->seedTenant(2);

        $ownerRepo = $this->repository(1);
        $id = $this->createDraft($ownerRepo);
        $ownerRepo->activate($id);
        $ownerRepo->addTarget($id, 'https://app.acme.test/login');

        $now = new DateTimeImmutable('2026-06-01 12:00:00');
        self::assertTrue($this->scopeManager(1, $ownerRepo)->checkRequest($id, 'https://app.acme.test/login', $now)['allowed']);

        // Tenant 2 cannot see tenant 1's authorization ...
        $otherRepo = $this->repository(2);
        self::assertNull($otherRepo->findById($id));

        // ... and therefore cannot use it to reach tenant 1's target.
        $result = $this->scopeManager(2, $otherRepo)->checkRequest($id, 'https://app.acme.test/login', $now);
        self::assertFalse($result['allowed']);
        self::assertSame('authorization_inactive_or_expired', $result['reason']);

        // The refusal is recorded against the tenant that attempted it, and
        // tenant 1's trail is untouched.
        self::assertSame(1, $this->denialEvents(2));
        self::assertSame(0, $this->denialEvents(1));
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private function repository(int $tenantId): AuthorizationRepository
    {
        return new AuthorizationRepository($this->pdo, $tenantId, new ScopedSecretStore(self::TEST_KEY));
    }

    private function scopeManager(int $tenantId, AuthorizationRepository $repo): ScopeManager
    {
        return new ScopeManager($repo, new AuditLogger($this->pdo), $tenantId);
    }

    private function createDraft(
        AuthorizationRepository $repo,
        string $proofType = 'dns-txt',
        ?DateTimeImmutable $validFrom = null,
        ?DateTimeImmutable $validTo = null,
        ?string $credential = null,
        bool $omitValidTo = false
    ): int {
        return $repo->create(
            clientName: 'Acme Manufacturing Ltd',
            techniqueProfile: ['passive-recon', 'authenticated-web-scan'],
            stopContact: 'soc@acme.test',
            ownershipProofType: $proofType,
            ownershipProofRef: 'dns TXT aiwebscapes-verify at acme.test',
            validFrom: $validFrom ?? new DateTimeImmutable('2026-01-01 00:00:00'),
            validTo: $omitValidTo ? null : ($validTo ?? new DateTimeImmutable('2026-12-31 23:59:59')),
            credential: $credential
        );
    }

    /**
     * A complete, active, in-window authorization row, with overrides applied.
     *
     * @param  array<string, scalar|null> $overrides
     * @return array<string, scalar|null>
     */
    private function row(array $overrides = []): array
    {
        return array_merge([
            'id' => 42,
            'tenant_id' => 1,
            'client_name' => 'Acme Manufacturing Ltd',
            'status' => 'active',
            'valid_from' => '2026-01-01 00:00:00',
            'valid_to' => '2026-12-31 23:59:59',
            'technique_profile' => '["passive-recon","authenticated-web-scan"]',
            'stop_contact' => 'soc@acme.test',
            'ownership_proof_type' => 'dns-txt',
            'ownership_proof_ref' => 'dns TXT aiwebscapes-verify at acme.test',
            'credentials_fingerprint' => 'sha256:0123456789abcdef',
        ], $overrides);
    }

    /**
     * Writes a row directly, bypassing the repository, to prove the
     * per-request gate does not trust a stored status.
     *
     * @param array<string, scalar|null> $overrides
     */
    private function insertAuthorization(int $tenantId, array $overrides = []): int
    {
        $row = array_merge($this->row(['tenant_id' => $tenantId]), $overrides);

        $statement = $this->pdo->prepare(
            'INSERT INTO security_authorizations ('
            . TenantScope::COLUMN . ', client_name, status, valid_from, valid_to, technique_profile,'
            . ' stop_contact, ownership_proof_type, ownership_proof_ref'
            . ') VALUES (:' . TenantScope::PARAM . ', :client_name, :status, :valid_from, :valid_to,'
            . ' :technique_profile, :stop_contact, :proof_type, :proof_ref)'
        );
        (new TenantScope($tenantId))->bindTo($statement);
        $statement->bindValue('client_name', $row['client_name']);
        $statement->bindValue('status', $row['status']);
        $statement->bindValue(
            'valid_from',
            $row['valid_from'],
            $row['valid_from'] === null ? PDO::PARAM_NULL : PDO::PARAM_STR
        );
        $statement->bindValue(
            'valid_to',
            $row['valid_to'],
            $row['valid_to'] === null ? PDO::PARAM_NULL : PDO::PARAM_STR
        );
        $statement->bindValue('technique_profile', $row['technique_profile']);
        $statement->bindValue('stop_contact', $row['stop_contact']);
        $statement->bindValue('proof_type', $row['ownership_proof_type']);
        $statement->bindValue('proof_ref', $row['ownership_proof_ref']);
        $statement->execute();

        return (int) $this->pdo->lastInsertId();
    }

    private function seedTenant(int $tenantId): void
    {
        $statement = $this->pdo->prepare(
            'INSERT IGNORE INTO tenants (id, slug, name, status, deployment_model)'
            . " VALUES (:id, :slug, :name, 'active', 'cloud')"
        );
        $statement->bindValue('id', $tenantId, PDO::PARAM_INT);
        $statement->bindValue('slug', 'secagent-tenant-' . $tenantId);
        $statement->bindValue('name', 'Security Agent Tenant ' . $tenantId);
        $statement->execute();
    }

    private function denialEvents(int $tenantId): int
    {
        $statement = $this->pdo->prepare(
            'SELECT COUNT(*) FROM audit_events WHERE ' . TenantScope::COLUMN . ' = :' . TenantScope::PARAM
            . " AND action = 'secauth.scope.deny'"
        );
        (new TenantScope($tenantId))->bindTo($statement);
        $statement->execute();

        return (int) $statement->fetchColumn();
    }

    private function lastDenialObjectId(int $tenantId): string
    {
        $statement = $this->pdo->prepare(
            'SELECT object_id FROM audit_events WHERE ' . TenantScope::COLUMN . ' = :' . TenantScope::PARAM
            . " AND action = 'secauth.scope.deny' ORDER BY id DESC LIMIT 1"
        );
        (new TenantScope($tenantId))->bindTo($statement);
        $statement->execute();

        return (string) $statement->fetchColumn();
    }
}
