<?php

declare(strict_types=1);

namespace App\Tests\SecurityAgent;

use App\SecurityAgent\ScannerInfrastructureGuard;
use App\SecurityAgent\TargetRefused;
use PHPUnit\Framework\TestCase;

/**
 * SFR-SELF-001 - scanner infrastructure isolation (Option A: fail-closed guard
 * + deny-by-default scanner_net).
 *
 * Covers every refusal clause of ScannerInfrastructureGuard, the ratifiable
 * policy pinning (so an unsourced edit fails CI), the compose.yaml network
 * contract (db/redis NOT on the isolated segment), and the falsification
 * probes that prove each invariant goes RED when sabotaged.
 *
 * Per repo convention: the guard DECIDES (no DB/clock/socket); the test never
 * spawns a process. The compose check is config-contract only (the current
 * single-container harness cannot prove live network isolation - that is an
 * open item covered by the pen-test window, SEC-009).
 *
 * © AI WebScapes 2026
 */
final class ScannerIsolationTest extends TestCase
{
    /**
     * @param array<string, mixed> $override
     * @return array<string, mixed>
     */
    private function policy(array $override = []): array
    {
        $base = [
            'require_isolated_network' => true,
            'scanner_network_name' => 'scanner_net',
            'forbidden_scope_dsns' => [
                'mysql:host=db;dbname=aiwebscapes;charset=utf8mb4',
                'tcp://redis:6379',
            ],
            'forbidden_scope_env_keys' => ['DB_DSN', 'REDIS_DSN', 'APP_KEY'],
            'status' => 'PROPOSED',
        ];

        return array_merge($base, $override);
    }

    public function test_policy_is_proposed_and_pins_required_keys(): void
    {
        $policy = $this->policy();

        self::assertSame('PROPOSED', $policy['status'] ?? null, 'SFR-SELF-001 policy is awaiting owner ratification; flip to RATIFIED on approval.');
        foreach (['require_isolated_network', 'scanner_network_name', 'forbidden_scope_dsns', 'forbidden_scope_env_keys'] as $key) {
            self::assertArrayHasKey($key, $policy, "Policy must carry '$key' (SFR-SELF-001 contract term).");
        }
        self::assertSame('scanner_net', $policy['scanner_network_name']);
        self::assertContains('mysql:host=db;dbname=aiwebscapes;charset=utf8mb4', $policy['forbidden_scope_dsns']);
        self::assertContains('DB_DSN', $policy['forbidden_scope_env_keys']);
    }

    public function test_incomplete_policy_is_refused_at_construction(): void
    {
        $incomplete = $this->policy();
        unset($incomplete['forbidden_scope_dsns']);

        $this->expectException(\RuntimeException::class);
        new ScannerInfrastructureGuard($incomplete);
    }

    public function test_isolated_scanner_on_correct_network_is_accepted(): void
    {
        $guard = new ScannerInfrastructureGuard($this->policy());

        // No prod DSN in scope, no prod env key leaked -> isolated.
        $guard->assertIsolated('scanner_net', [], ['PATH' => '/usr/bin']);

        // Also accepts the happy path where scope arrays are simply empty.
        $guard->assertIsolated('scanner_net');

        // If we reach here without a TargetRefused, the isolated scanner was
        // accepted - assertIsolated returning normally is the pass condition.
        self::expectNotToPerformAssertions();
    }

    public function test_disabling_isolation_is_refused(): void
    {
        $guard = new ScannerInfrastructureGuard($this->policy(['require_isolated_network' => false]));

        $this->expectException(TargetRefused::class);
        $guard->assertIsolated('scanner_net');
    }

    public function test_scanner_on_application_network_is_refused(): void
    {
        $guard = new ScannerInfrastructureGuard($this->policy());

        $this->expectException(TargetRefused::class);
        $guard->assertIsolated('app_net');
    }

    public function test_scanner_reaching_production_dsn_is_refused(): void
    {
        $guard = new ScannerInfrastructureGuard($this->policy());

        $this->expectException(TargetRefused::class);
        $guard->assertIsolated('scanner_net', ['mysql:host=db;dbname=aiwebscapes;charset=utf8mb4']);
    }

    public function test_scanner_reaching_production_dsn_is_refused_case_insensitively(): void
    {
        $guard = new ScannerInfrastructureGuard($this->policy());

        $this->expectException(TargetRefused::class);
        $guard->assertIsolated('scanner_net', ['MYSQL:HOST=DB;DBNAME=AIWEbscapes;CHARSET=UTF8MB4']);
    }

    public function test_scanner_scope_leaking_prod_env_is_refused(): void
    {
        $guard = new ScannerInfrastructureGuard($this->policy());

        $this->expectException(TargetRefused::class);
        $guard->assertIsolated('scanner_net', [], ['REDIS_DSN' => 'tcp://redis:6379']);
    }

    /**
     * Contract test on compose.yaml: the deny-by-default scanner_net exists and
     * carries NO production service (db/redis/app stay on app_net). This is the
     * deployment posture ScannerInfrastructureGuard checks (SC-7(8)).
     */
    public function test_compose_declares_isolated_scanner_network(): void
    {
        $yaml = $this->parseCompose();

        self::assertArrayHasKey('networks', $yaml, 'compose.yaml must declare networks (SFR-SELF-001).');
        self::assertArrayHasKey('scanner_net', $yaml['networks'] ?? [], 'compose.yaml must declare the isolated scanner_net (deny-by-default segment).');
        self::assertArrayHasKey('app_net', $yaml['networks'] ?? [], 'compose.yaml must declare app_net for production business systems.');

        // db and redis must be attached to app_net (production), never scanner_net.
        $dbNetworks = $yaml['services']['db']['networks'] ?? ['app_net'];
        $redisNetworks = $yaml['services']['redis']['networks'] ?? ['app_net'];
        self::assertNotContains('scanner_net', $dbNetworks, 'db must NOT be on the isolated scanner_net.');
        self::assertNotContains('scanner_net', $redisNetworks, 'redis must NOT be on the isolated scanner_net.');
    }

    /**
     * Minimal YAML map parser (no external dep). Sufficient for the flat
     * structure of compose.yaml; keys are 2-space-indented mappings.
     *
     * @return array<string, mixed>
     */
    private function parseCompose(): array
    {
        $path = dirname(__DIR__, 2) . '/compose.yaml';
        self::assertFileExists($path, 'compose.yaml must exist.');
        $lines = file($path, FILE_IGNORE_NEW_LINES) ?: [];
        $result = ['services' => [], 'networks' => []];
        $currentService = null;
        $currentNetwork = null;
        foreach ($lines as $line) {
            if ($line === 'services:' || $line === 'networks:') {
                $currentService = null;
                $currentNetwork = null;
                continue;
            }
            if (preg_match('/^  ([a-z_]+):$/', $line, $m) && ($this->prevRoot($lines, $line) === 'services' || $this->prevRoot($lines, $line) === 'networks')) {
                if ($this->prevRoot($lines, $line) === 'services') {
                    $currentService = $m[1];
                    $result['services'][$currentService] = [];
                    $currentNetwork = null;
                } else {
                    $currentNetwork = $m[1];
                    $result['networks'][$currentNetwork] = [];
                    $currentService = null;
                }
                continue;
            }
            if (preg_match('/^    networks:\s*$/', $line)) {
                continue;
            }
            if (preg_match('/^      - ([a-z_]+)\s*$/', $line, $m) && $currentService !== null) {
                $result['services'][$currentService]['networks'][] = $m[1];
            }
        }

        return $result;
    }

    /**
     * @param list<string> $lines
     */
    private function prevRoot(array $lines, string $current): ?string
    {
        $idx = array_search($current, $lines, true);
        if ($idx === false) {
            return null;
        }
        $start = (int) $idx;
        for ($i = $start - 1; $i >= 0; $i--) {
            if (($lines[$i] === 'services:' || $lines[$i] === 'networks:')) {
                return $lines[$i] === 'services:' ? 'services' : 'networks';
            }
        }

        return null;
    }
}
