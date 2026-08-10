<?php

declare(strict_types=1);

namespace App\Tests\SecurityAgent;

use App\Audit\AuditLogger;
use App\SecurityAgent\Asset;
use App\SecurityAgent\AssetRepository;
use App\SecurityAgent\AuthorizationRepository;
use App\SecurityAgent\ScannerAdapter;
use App\SecurityAgent\ScannerResult;
use App\SecurityAgent\ScanProfileRepository;
use App\SecurityAgent\ScanRepository;
use App\SecurityAgent\SecurityScan;
use App\Tests\TestCase;
use DateTimeImmutable;
use DateTimeZone;
use PDO;
use RuntimeException;

/**
 * P3-T3 - Asset discovery / inventory and sandboxed scanner adapters.
 *
 * Each test maps to a baseline requirement:
 *
 *  - SFR-ASSET-001: the inventory is VERSIONED and records first seen, last
 *    seen, source, confidence, owner, environment and criticality. Re-seeing
 *    an asset is a new version, not an overwrite of the history.
 *  - SFR-SCAN-001: a scan profile is immutable once a scan has COMPLETED under
 *    it - the completion transition itself freezes the envelope.
 *  - SFR-SCAN-002: adapters are version-pinned and produce machine-readable
 *    results - a typed structure, never a blob of text to be regexed.
 *  - SFR-SCAN-003: a tool failure is NOT a target vulnerability. The failure
 *    state and its evidence (message, exit code) are recorded as a failure.
 *  - SFR-SELF-002: an untrusted adapter is disabled, and a disabled adapter
 *    does not run - the executor is never even reached.
 *  - AC-001: none of the inventory is visible across a tenant boundary.
 *
 * WHY THE SCANNER TESTS INJECT THE EXECUTOR. The adapter is the ACTOR, but the
 * decision layer stays pure: the thing that touches the network is a callable
 * handed in from outside, so every classification path - success, throw,
 * error-shaped output, refusal - is provable without a socket.
 *
 * © AI WebScapes 2026
 */
final class AssetAndScannerTest extends TestCase
{
    // ---------------------------------------------------------------
    // SFR-ASSET-001 - versioned inventory with first/last seen
    // ---------------------------------------------------------------

    public function test_asset_inventory_is_versioned_and_tracks_seen(): void
    {
        $this->seedTenant(1);
        $assets = $this->assets(1);

        $firstSighting = $this->at('2026-01-05 09:00:00');
        $secondSighting = $this->at('2026-03-11 17:45:00');

        $id = $assets->upsert('app.acme.test', [
            'asset_type' => 'host',
            'environment' => 'production',
            'owner' => 'platform-team@acme.test',
            'criticality' => 'high',
            'confidence' => 'high',
            'source' => 'dns-enumeration',
            'discovery_meta' => ['ports' => [443]],
        ], $firstSighting);

        $recorded = $assets->findById($id);
        self::assertInstanceOf(Asset::class, $recorded);
        self::assertSame(1, $recorded->version(), 'A newly discovered asset is version 1.');
        self::assertSame('app.acme.test', $recorded->canonicalAsset());
        self::assertSame('2026-01-05 09:00:00', $this->stamp($recorded->firstSeen()));
        self::assertSame('2026-01-05 09:00:00', $this->stamp($recorded->lastSeen()));

        // Every attribute SFR-ASSET-001 names is carried on the row.
        self::assertSame('host', $recorded->assetType());
        self::assertSame('production', $recorded->environment());
        self::assertSame('platform-team@acme.test', $recorded->owner());
        self::assertSame('high', $recorded->criticality());
        self::assertSame('high', $recorded->confidence());
        self::assertSame('dns-enumeration', $recorded->source());

        // Seeing it again is an UPSERT: same row, next version, last_seen moved
        // forward, and the discovery metadata merged rather than replaced.
        $again = $assets->upsert('app.acme.test', [
            'discovery_meta' => ['tls' => 'tls1.3'],
        ], $secondSighting);
        self::assertSame($id, $again, 'Re-discovery must not create a second row.');

        $updated = $assets->findById($id);
        self::assertInstanceOf(Asset::class, $updated);
        self::assertSame(2, $updated->version(), 'Re-discovery bumps the version (SFR-ASSET-001).');
        self::assertSame(
            '2026-01-05 09:00:00',
            $this->stamp($updated->firstSeen()),
            'first_seen is history and must never move.'
        );
        self::assertSame('2026-03-11 17:45:00', $this->stamp($updated->lastSeen()));

        // Attributes not restated by the sighting survive it.
        self::assertSame('platform-team@acme.test', $updated->owner());
        self::assertSame('high', $updated->criticality());
        self::assertSame('dns-enumeration', $updated->source());
        self::assertSame([443], $updated->discoveryMeta()['ports'] ?? null);
        self::assertSame('tls1.3', $updated->discoveryMeta()['tls'] ?? null);

        // The value object is immutable: a bump produces a NEW asset.
        $bumped = $updated->bumpVersion($this->at('2026-04-01 00:00:00'));
        self::assertSame(3, $bumped->version());
        self::assertSame(2, $updated->version(), 'bumpVersion() must not mutate the original.');
        self::assertSame('2026-04-01 00:00:00', $this->stamp($bumped->lastSeen()));
        self::assertSame('2026-01-05 09:00:00', $this->stamp($bumped->firstSeen()));
    }

    public function test_asset_of_a_different_type_is_a_different_asset(): void
    {
        $this->seedTenant(1);
        $assets = $this->assets(1);

        $host = $assets->upsert('app.acme.test', ['asset_type' => 'host']);
        $domain = $assets->upsert('app.acme.test', ['asset_type' => 'domain']);

        self::assertNotSame($host, $domain);
        self::assertCount(2, $assets->findByCanonical('app.acme.test'));
    }

    // ---------------------------------------------------------------
    // AC-001 - the inventory does not cross a tenant boundary
    // ---------------------------------------------------------------

    public function test_asset_is_tenant_scoped(): void
    {
        $this->seedTenant(1);
        $this->seedTenant(2);

        $id = $this->assets(1)->upsert('vpn.acme.test', ['owner' => 'net-ops@acme.test']);

        $intruder = $this->assets(2);
        self::assertNull($intruder->findById($id), 'Another tenant must not read the asset.');
        self::assertSame([], $intruder->findByCanonical('vpn.acme.test'));

        // ... and the owner still sees it, so the assertion above is about the
        // tenant boundary and not about an absent row.
        self::assertNotNull($this->assets(1)->findById($id));
        self::assertCount(1, $this->assets(1)->findByCanonical('vpn.acme.test'));

        // An upsert of the same name under tenant 2 creates tenant 2's OWN row.
        $theirs = $intruder->upsert('vpn.acme.test', []);
        self::assertNotSame($id, $theirs);
        self::assertNull($this->assets(1)->findById($theirs));
    }

    // ---------------------------------------------------------------
    // SFR-SCAN-002 - version-pinned adapter, machine-readable result
    // ---------------------------------------------------------------

    public function test_scanner_adapter_runs_with_version(): void
    {
        $calls = 0;
        $adapter = new ScannerAdapter(
            'nmap',
            '7.94',
            function (string $target) use (&$calls): array {
                $calls++;

                return [
                    'status' => 'finding',
                    'data' => ['open_ports' => [443], 'probed' => $target],
                ];
            },
            true
        );

        self::assertSame('nmap', $adapter->name());
        self::assertSame('7.94', $adapter->version(), 'The adapter is version-pinned (SFR-SELF-002).');

        $result = $adapter->run('app.acme.test');

        self::assertSame(1, $calls);
        self::assertInstanceOf(ScannerResult::class, $result);
        self::assertSame('finding', $result->status);
        self::assertSame('nmap', $result->scanner);
        self::assertSame('app.acme.test', $result->target);
        self::assertSame([443], $result->data['open_ports'] ?? null);
        self::assertSame('app.acme.test', $result->data['probed'] ?? null);
        self::assertNull($result->errorMessage);
        self::assertSame(0, $result->exitCode);

        // Machine-readable means a typed shape, not a string to be regexed.
        $machine = $result->toMachineArray();
        self::assertSame(
            ['scanner', 'target', 'status', 'data', 'error_message', 'exit_code', 'recorded_at'],
            array_keys($machine)
        );
        self::assertSame('finding', $machine['status']);
        self::assertSame([443], $machine['data']['open_ports'] ?? null);
        // recorded_at is a UTC timestamp string (machine-readable, not a fuzzy blob).
        self::assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/', $machine['recorded_at']);
    }

    public function test_scanner_result_refuses_an_unknown_status(): void
    {
        $this->expectException(RuntimeException::class);

        new ScannerResult('nmap', 'app.acme.test', 'probably-vulnerable', []);
    }

    // ---------------------------------------------------------------
    // SFR-SELF-002 - disabled when untrusted
    // ---------------------------------------------------------------

    public function test_scanner_adapter_disabled_when_untrusted(): void
    {
        $calls = 0;
        $adapter = new ScannerAdapter(
            'nuclei',
            '3.1.0',
            function (string $target) use (&$calls): array {
                $calls++;

                return ['status' => 'finding', 'data' => ['target' => $target]];
            },
            false
        );

        $result = $adapter->run('app.acme.test');

        self::assertSame('refused', $result->status);
        self::assertNotSame('finding', $result->status);
        self::assertSame(0, $calls, 'A disabled adapter must never reach its executor.');
        self::assertIsString($result->errorMessage);
        self::assertFalse($adapter->isEnabled());
    }

    // ---------------------------------------------------------------
    // SFR-SCAN-003 - a tool failure is NOT a target vulnerability
    // ---------------------------------------------------------------

    public function test_tool_failure_is_not_a_vulnerability(): void
    {
        $thrower = new ScannerAdapter('nmap', '7.94', function (string $target): array {
            throw new RuntimeException('connect to ' . $target . ' failed: network unreachable');
        });

        $result = $thrower->run('app.acme.test');

        // THE requirement: the tool broke, so the result is a FAILURE STATE -
        // never a finding about the target.
        self::assertSame('error', $result->status);
        self::assertNotSame('finding', $result->status, 'A tool failure must never become a finding.');
        self::assertIsString($result->errorMessage);
        self::assertStringContainsString('network unreachable', $result->errorMessage);
        self::assertSame(1, $result->exitCode);
        self::assertSame([], $result->data, 'A failed run yields no findings data.');

        $machine = $result->toMachineArray();
        self::assertSame('error', $machine['status']);
        self::assertStringContainsString('network unreachable', (string) $machine['error_message']);
        self::assertSame(1, $machine['exit_code']);

        // The same guarantee when the tool reports failure through its OUTPUT
        // rather than by throwing: still a failure state, still not a finding.
        $crasher = new ScannerAdapter('nmap', '7.94', fn (string $target): array => [
            'status' => 'error',
            'error' => 'segmentation fault while probing ' . $target,
            'exit_code' => 139,
        ]);

        $crashed = $crasher->run('app.acme.test');
        self::assertSame('error', $crashed->status);
        self::assertNotSame('finding', $crashed->status);
        self::assertSame(139, $crashed->exitCode);
        self::assertStringContainsString('segmentation fault', (string) $crashed->errorMessage);

        // An unrecognised status is not trusted into the finding path either.
        $liar = new ScannerAdapter('nmap', '7.94', fn (): array => ['status' => 'pwned', 'data' => []]);
        $lied = $liar->run('app.acme.test');
        self::assertSame('error', $lied->status);
        self::assertNotSame('finding', $lied->status);
    }

    public function test_scanner_result_failure_factory(): void
    {
        $result = ScannerResult::failure('tls-probe', 'app.acme.test', 'handshake timed out', 124);

        self::assertSame('error', $result->status);
        self::assertNotSame('finding', $result->status);
        self::assertSame('tls-probe', $result->scanner);
        self::assertSame('app.acme.test', $result->target);
        self::assertSame('handshake timed out', $result->errorMessage);
        self::assertSame(124, $result->exitCode);
        self::assertSame([], $result->data);
        self::assertFalse($result->isFinding());
        self::assertTrue($result->isFailure());
    }

    // ---------------------------------------------------------------
    // SFR-SCAN-001 - completing a scan freezes the profile it ran under
    // ---------------------------------------------------------------

    public function test_completed_scan_freezes_profile(): void
    {
        $this->seedTenant(1);
        $profiles = $this->profiles(1);
        $scans = $this->scans(1);
        $authorizationId = $this->authorization(1);

        $profileId = $profiles->create($authorizationId, ['tls-config'], destructiveChecksEnabled: true);
        self::assertFalse($profiles->requireById($profileId)->isImmutable());

        $scanId = $scans->schedule($authorizationId, $profileId, 1);
        self::assertTrue($scans->start($scanId));

        self::assertTrue($scans->completeAndFreeze($scanId, $profileId));
        self::assertSame(SecurityScan::STATUS_COMPLETED, $scans->requireById($scanId)->status());
        self::assertTrue(
            $profiles->requireById($profileId)->isImmutable(),
            'A completed scan freezes its profile (SFR-SCAN-001).'
        );

        // The freeze is evidenced, not silent.
        self::assertSame(1, $scans->countEvents($scanId, 'profile_frozen'));

        // Completing again is refused: the transition is one-way.
        self::assertFalse($scans->completeAndFreeze($scanId, $profileId));

        // And the frozen envelope cannot be re-approved after the fact, which
        // is what makes the completed report un-reinterpretable.
        $this->expectException(RuntimeException::class);
        $profiles->approveDestructiveChecks($profileId, 77);
    }

    public function test_freeze_refuses_a_profile_the_scan_did_not_run_under(): void
    {
        $this->seedTenant(1);
        $profiles = $this->profiles(1);
        $scans = $this->scans(1);
        $authorizationId = $this->authorization(1);

        $ranUnder = $profiles->create($authorizationId, ['tls-config']);
        $untouched = $profiles->create($authorizationId, ['http-headers']);

        $scanId = $scans->schedule($authorizationId, $ranUnder, 1);
        $scans->start($scanId);

        try {
            $scans->completeAndFreeze($scanId, $untouched);
            self::fail('Freezing a profile the scan never used must be refused.');
        } catch (RuntimeException) {
            // Expected.
        }

        self::assertFalse($profiles->requireById($untouched)->isImmutable());
        self::assertSame(SecurityScan::STATUS_RUNNING, $scans->requireById($scanId)->status());
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private function assets(int $tenantId): AssetRepository
    {
        return new AssetRepository($this->pdo, $tenantId);
    }

    private function profiles(int $tenantId): ScanProfileRepository
    {
        return new ScanProfileRepository($this->pdo, $tenantId, new AuditLogger($this->pdo));
    }

    private function scans(int $tenantId): ScanRepository
    {
        return new ScanRepository($this->pdo, $tenantId);
    }

    private function at(string $moment): DateTimeImmutable
    {
        return new DateTimeImmutable($moment, new DateTimeZone('UTC'));
    }

    private function stamp(DateTimeImmutable $moment): string
    {
        return $moment->format('Y-m-d H:i:s');
    }

    /**
     * A recorded authorization for the profile to hang off (P3-T1 owns its
     * lifecycle; here it only has to exist and belong to this tenant).
     */
    private function authorization(int $tenantId): int
    {
        return (new AuthorizationRepository($this->pdo, $tenantId))->create(
            clientName: 'Acme Manufacturing Ltd',
            techniqueProfile: ['passive-recon', 'authenticated-web-scan'],
            stopContact: 'soc@acme.test',
            ownershipProofType: 'dns-txt',
            ownershipProofRef: 'dns TXT aiwebscapes-verify at acme.test',
            validFrom: new DateTimeImmutable('2026-01-01 00:00:00'),
            validTo: new DateTimeImmutable('2026-12-31 23:59:59')
        );
    }

    private function seedTenant(int $tenantId): void
    {
        $statement = $this->pdo->prepare(
            'INSERT IGNORE INTO tenants (id, slug, name, status, deployment_model)'
            . " VALUES (:id, :slug, :name, 'active', 'cloud')"
        );
        $statement->bindValue('id', $tenantId, PDO::PARAM_INT);
        $statement->bindValue('slug', 'asset-tenant-' . $tenantId);
        $statement->bindValue('name', 'Asset Inventory Tenant ' . $tenantId);
        $statement->execute();
    }
}
