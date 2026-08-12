<?php

declare(strict_types=1);

namespace App\Tests\SecurityAgent;

use App\Audit\AuditLogger;
use App\SecurityAgent\AssetRepository;
use App\SecurityAgent\AuthorizationRepository;
use App\SecurityAgent\Evidence;
use App\SecurityAgent\EvidenceProcessor;
use App\SecurityAgent\EvidenceRedactionRequired;
use App\SecurityAgent\EvidenceRepository;
use App\SecurityAgent\RedactionScanner;
use App\SecurityAgent\ScanProfileRepository;
use App\SecurityAgent\ScanRepository;
use App\SecurityAgent\ScannerResult;
use App\Tests\TestCase;
use DateTimeImmutable;
use DateTimeZone;
use PDO;

/**
 * P3-T4 - Evidence Processor (first component of the SFR-EVID/SFR-FIND/SFR-AI
 * grouping).
 *
 * Each test maps to a baseline requirement:
 *
 *  - SFR-EVID-001: evidence shall include scanner/version, target, timestamp,
 *    request category, response metadata, reproduction and a cryptographic hash
 *    where stored as artifact. The processor builds exactly those fields and a
 *    deterministic sha256 of the canonicalized content.
 *  - SFR-EVID-002: secrets, session identifiers, personal data and unnecessary
 *    response bodies shall be redacted BEFORE routine display. The processor
 *    redacts them and records the kinds it removed, and REFUSES (fail-closed)
 *    to hand back an unredacted item when redaction is not permitted.
 *  - SFR-FIND-002 (foundation): repeated evidence shall update occurrence
 *    history without destroying previous state - the content hash lets the
 *    caller locate a prior observation instead of duplicating it.
 *  - AC-001: evidence is not visible across a tenant boundary.
 *
 * WHY THE PROCESSOR IS TESTED PURE. EvidenceProcessor touches no database, no
 * clock beyond its own injected moment, and no socket - so the redact / refuse
 * / hash / fingerprint paths are all provable with plain value objects.
 *
 * © AI WebScapes 2026
 */
final class EvidenceProcessorTest extends TestCase
{
    // ---------------------------------------------------------------
    // SFR-EVID-001 - complete evidence with a cryptographic hash
    // ---------------------------------------------------------------

    public function test_evidence_captures_every_required_field_and_hash(): void
    {
        $this->seedTenant(1);
        $scans = $this->scans(1);
        $scanId = $this->scheduleScan(1);

        $result = new ScannerResult(
            'nmap',
            'app.acme.test',
            ScannerResult::STATUS_FINDING,
            ['open_ports' => [443]],
            null,
            0,
            $this->at('2026-02-10 11:00:00')
        );

        $metadata = ['open_ports' => [443], 'banner' => 'nginx'];
        $repro = ['command' => 'nmap -p 443 app.acme.test'];

        $evidence = $this->processor()->process(
            tenantId: 1,
            scanId: $scanId,
            assetId: null,
            result: $result,
            scannerVersion: '7.94',
            requestCategory: 'port-scan',
            responseMetadata: $metadata,
            reproduction: $repro,
            capturedAt: $this->at('2026-02-10 11:00:00')
        );

        self::assertInstanceOf(Evidence::class, $evidence);
        // Everything SFR-EVID-001 names is present.
        self::assertSame('nmap', $evidence->scanner());
        self::assertSame('7.94', $evidence->scannerVersion());
        self::assertSame('app.acme.test', $evidence->target());
        self::assertSame('2026-02-10 11:00:00', $this->stamp($evidence->capturedAt()));
        self::assertSame('port-scan', $evidence->requestCategory());
        self::assertSame($metadata, $evidence->responseMetadata());
        self::assertSame($repro, $evidence->reproduction());
        // The content hash is a sha256 (64 hex chars).
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $evidence->contentHash());
        // No sensitive data here, so nothing was redacted.
        self::assertFalse($evidence->wasRedacted());
        self::assertSame([], $evidence->redactionKinds());

        // And it stores and round-trips through the repository.
        $id = $this->evidence(1)->store($evidence);
        $stored = $this->evidence(1)->findById($id);
        self::assertInstanceOf(Evidence::class, $stored);
        self::assertSame($evidence->contentHash(), $stored->contentHash());
        self::assertSame('nmap', $stored->scanner());
    }

    public function test_content_hash_is_deterministic_for_identical_observations(): void
    {
        $result = new ScannerResult('nmap', 'app.acme.test', ScannerResult::STATUS_FINDING, ['port' => 443]);

        $a = $this->processor()->process(
            1,
            1,
            null,
            $result,
            '7.94',
            'port-scan',
            ['port' => 443, 'extra' => 'x'],
            ['command' => 'nmap']
        );
        // Same logical content, different KEY ORDER - must still hash identically.
        $b = $this->processor()->process(
            1,
            1,
            null,
            $result,
            '7.94',
            'port-scan',
            ['extra' => 'x', 'port' => 443],
            ['command' => 'nmap']
        );

        self::assertSame(
            $a->contentHash(),
            $b->contentHash(),
            'Key order must not change the canonical hash (SFR-EVID-001).'
        );

        // Different target -> different hash.
        $c = $this->processor()->process(
            1,
            1,
            null,
            new ScannerResult('nmap', 'other.acme.test', ScannerResult::STATUS_FINDING, ['port' => 443]),
            '7.94',
            'port-scan',
            ['port' => 443, 'extra' => 'x'],
            ['command' => 'nmap']
        );
        self::assertNotSame($a->contentHash(), $c->contentHash(), 'A different target must change the hash.');
    }

    // ---------------------------------------------------------------
    // SFR-EVID-002 - redaction BEFORE display/storage
    // ---------------------------------------------------------------

    public function test_secret_in_response_metadata_is_redacted_and_fingerprinted(): void
    {
        $result = new ScannerResult('nmap', 'app.acme.test', ScannerResult::STATUS_INFO, []);

        // Fixture generated at runtime (never hard-coded): a session-token-shaped
        // value the redaction engine is asserted to strip.
        $sessionToken = 'sess_' . bin2hex(random_bytes(6));

        $evidence = $this->processor()->process(
            1,
            1,
            null,
            $result,
            '7.94',
            'auth-probe',
            ['token' => $sessionToken, 'status' => 'ok'],
            null,
            $this->at('2026-02-10 12:00:00')
        );

        // The secret is GONE, replaced by a marker.
        $stored = $evidence->responseMetadata();
        self::assertNotContains($sessionToken, $stored, 'The session token must not survive.');
        self::assertSame(RedactionScanner::markerFor('session_token'), $stored['token'] ?? null);
        self::assertSame('ok', $stored['status'] ?? null, 'Non-sensitive values are untouched.');

        // The kind is fingerprinted, and redactedAt is set.
        self::assertSame(['session_token'], $evidence->redactionKinds());
        self::assertTrue($evidence->wasRedacted());
        self::assertSame('2026-02-10 12:00:00', $this->stamp($evidence->redactedAt()));
    }

    public function test_multiple_sensitive_kinds_are_all_fingerprinted(): void
    {
        $result = new ScannerResult('curl', 'app.acme.test', ScannerResult::STATUS_INFO, []);

        $evidence = $this->processor()->process(
            1,
            1,
            null,
            $result,
            '7.94',
            'response-headers',
            [
                'authorization' => 'Bearer abcd1234',
                'email' => 'jane.doe@acme.test',
                'response_body' => '<html>secret page</html>',
                'port' => 443,
            ]
        );

        self::assertSame(
            ['personal_data', 'response_body', 'session_token'],
            $evidence->redactionKinds(),
            'All three SFR-EVID-002 kinds must be detected (order-stable).'
        );
        $stored = $evidence->responseMetadata();
        self::assertSame(RedactionScanner::markerFor('session_token'), $stored['authorization'] ?? null);
        self::assertSame(RedactionScanner::markerFor('personal_data'), $stored['email'] ?? null);
        self::assertSame(RedactionScanner::markerFor('response_body'), $stored['response_body'] ?? null);
        self::assertSame(443, $stored['port'] ?? null);
    }

    public function test_processor_refuses_unredacted_sensitive_evidence(): void
    {
        $result = new ScannerResult('curl', 'app.acme.test', ScannerResult::STATUS_INFO, []);

        try {
            $this->processor()->process(
                1,
                1,
                null,
                $result,
                '7.94',
                'auth-probe',
                ['password' => 'hunter2'],
                null,
                allowRedaction: false // caller insists on no redaction
            );
            self::fail('Expected EvidenceRedactionRequired to be thrown.');
        } catch (EvidenceRedactionRequired $e) {
            self::assertSame(['secret'], $e->kinds());
            self::assertStringContainsString('SFR-EVID-002', $e->getMessage());
        }
    }

    public function test_redaction_is_allowlist_driven_not_pattern_hunt(): void
    {
        // A benign long hex that is NOT under a sensitive key must NOT be
        // redacted - the scanner reasons about KINDS (AC-002 allowlist).
        $result = new ScannerResult('nmap', 'app.acme.test', ScannerResult::STATUS_INFO, []);
        $evidence = $this->processor()->process(
            1,
            1,
            null,
            $result,
            '7.94',
            'banner-grab',
            ['banner' => 'deadbeefdeadbeefdeadbeefdeadbeef'],
        );
        self::assertFalse($evidence->wasRedacted(), 'A long hex under a benign key stays.');

        // ... but the same value under a known-credential key IS redacted.
        $secret = $this->processor()->process(
            1,
            1,
            null,
            $result,
            '7.94',
            'banner-grab',
            ['api_key' => 'deadbeefdeadbeefdeadbeefdeadbeef'],
        );
        self::assertTrue($secret->wasRedacted());
        self::assertSame(['secret'], $secret->redactionKinds());
    }

    // ---------------------------------------------------------------
    // SFR-FIND-002 foundation - hash supports dedupe without history loss
    // ---------------------------------------------------------------

    public function test_repeated_evidence_is_locatable_by_hash_not_duplicated(): void
    {
        $this->seedTenant(1);
        $repo = $this->evidence(1);
        $scanId = $this->scheduleScan(1);
        $result = new ScannerResult('nmap', 'app.acme.test', ScannerResult::STATUS_FINDING, ['port' => 443]);

        $first = $this->processor()->process(
            1,
            $scanId,
            null,
            $result,
            '7.94',
            'port-scan',
            ['port' => 443],
        );
        $id1 = $repo->store($first);

        // A later scan makes the SAME observation.
        $again = $this->processor()->process(
            1,
            $scanId,
            null,
            $result,
            '7.94',
            'port-scan',
            ['port' => 443],
        );
        // The hash is identical, so the caller can LOCATE the prior item...
        self::assertSame($first->contentHash(), $again->contentHash());

        $prior = $repo->findByHash($again->contentHash());
        self::assertCount(1, $prior, 'Exactly one prior observation exists.');
        self::assertSame($id1, $prior[0]->id());

        // ... and choose to attach a NEW occurrence rather than overwrite. The
        // original row is preserved (history is not destroyed).
        $id2 = $repo->store($again);
        self::assertNotSame($id1, $id2, 'A new occurrence gets its own row.');
        self::assertCount(2, $repo->findByHash($again->contentHash()), 'Both occurrences survive.');
    }

    // ---------------------------------------------------------------
    // AC-001 - evidence does not cross a tenant boundary
    // ---------------------------------------------------------------

    public function test_evidence_is_tenant_scoped(): void
    {
        $this->seedTenant(1);
        $this->seedTenant(2);

        $repo1 = $this->evidence(1);
        $scanId = $this->scheduleScan(1);
        $result = new ScannerResult('nmap', 'app.acme.test', ScannerResult::STATUS_INFO, []);

        $id = $repo1->store($this->processor()->process(
            1,
            $scanId,
            null,
            $result,
            '7.94',
            'port-scan',
            ['port' => 443],
        ));

        $repo2 = $this->evidence(2);
        self::assertNull($repo2->findById($id), 'Another tenant must not read the evidence.');
        self::assertCount(0, $repo2->forScan($scanId));
        // ... and tenant 1 still sees it, so the denial is about the boundary.
        self::assertNotNull($repo1->findById($id));
        self::assertCount(1, $repo1->forScan($scanId));
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private function processor(): EvidenceProcessor
    {
        return new EvidenceProcessor();
    }

    private function evidence(int $tenantId): EvidenceRepository
    {
        return new EvidenceRepository($this->pdo, $tenantId);
    }

    private function scans(int $tenantId): ScanRepository
    {
        return new ScanRepository($this->pdo, $tenantId);
    }

    /**
     * Builds a real authorization -> profile -> scheduled scan so evidence can
     * link to a legitimate scan row owned by this tenant.
     */
    private function scheduleScan(int $tenantId): int
    {
        $authId = (new AuthorizationRepository($this->pdo, $tenantId))->create(
            clientName: 'Acme Manufacturing Ltd',
            techniqueProfile: ['passive-recon'],
            stopContact: 'soc@acme.test',
            ownershipProofType: 'dns-txt',
            ownershipProofRef: 'dns TXT aiwebscapes-verify at acme.test',
            validFrom: new DateTimeImmutable('2026-01-01 00:00:00'),
            validTo: new DateTimeImmutable('2026-12-31 23:59:59')
        );
        $profileId = (new ScanProfileRepository($this->pdo, $tenantId, new AuditLogger($this->pdo)))
            ->create($authId, ['port-scan']);
        $profile = (new ScanProfileRepository($this->pdo, $tenantId, new AuditLogger($this->pdo)))
            ->requireById($profileId);

        return $this->scans($tenantId)->schedule($authId, $profileId, $profile->version());
    }

    private function at(string $moment): DateTimeImmutable
    {
        return new DateTimeImmutable($moment, new DateTimeZone('UTC'));
    }

    private function stamp(?DateTimeImmutable $moment): string
    {
        return $moment?->format('Y-m-d H:i:s') ?? '';
    }

    private function seedTenant(int $tenantId): void
    {
        $statement = $this->pdo->prepare(
            'INSERT IGNORE INTO tenants (id, slug, name, status, deployment_model)'
            . " VALUES (:id, :slug, :name, 'active', 'cloud')"
        );
        $statement->bindValue('id', $tenantId, PDO::PARAM_INT);
        $statement->bindValue('slug', 'evidence-tenant-' . $tenantId);
        $statement->bindValue('name', 'Evidence Tenant ' . $tenantId);
        $statement->execute();
    }
}
