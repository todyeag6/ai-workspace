<?php

declare(strict_types=1);

namespace App\Tests\Deploy;

use App\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * P4-T1 — Ratifiable hardware-sizing policy (BRD Phase 4 #1, BR-9.2).
 * The pinning test loads the REAL shipped file and asserts the contract terms
 * (status + required tier keys). It must fail if the file is missing, malformed,
 * or silently changed — that is the point of a RATIFY gate.
 */
final class HardwareSizingTest extends TestCase
{
    private const POLICY_PATH = __DIR__ . '/../../config/deploy/HARDWARE_SIZING.php';

    private const TIERS = ['small', 'medium', 'large'];

    private const REQUIRED_KEYS = [
        'cpu_cores', 'ram_gb', 'disk_gb', 'ollama_models', 'max_tenants', 'notes',
    ];

    #[Test]
    public function test_policy_file_exists_and_returns_array(): void
    {
        self::assertFileExists(self::POLICY_PATH, 'HARDWARE_SIZING policy must exist.');
        $policy = require self::POLICY_PATH;
        self::assertIsArray($policy, 'Policy must return an array.');
    }

    #[Test]
    public function test_policy_is_ratified_by_owner(): void
    {
        $policy = require self::POLICY_PATH;
        self::assertSame(
            'RATIFIED',
            $policy['status'] ?? null,
            'Hardware sizing profile is RATIFIED (owner sign-off 2026-08-12).'
        );
    }

    #[Test]
    public function test_policy_pins_all_required_tier_keys(): void
    {
        $policy = require self::POLICY_PATH;
        self::assertArrayHasKey('profiles', $policy, 'Policy must declare profiles.');
        self::assertIsArray($policy['profiles']);

        foreach (self::TIERS as $tier) {
            self::assertArrayHasKey($tier, $policy['profiles'], "Tier '$tier' must be defined.");
            $profile = $policy['profiles'][$tier];
            self::assertIsArray($profile, "Tier '$tier' profile must be an array.");
            foreach (self::REQUIRED_KEYS as $key) {
                self::assertArrayHasKey($key, $profile, "Tier '$tier' must declare '$key'.");
            }
            self::assertIsArray($profile['ollama_models'], "Tier '$tier' ollama_models must be a list.");
            self::assertIsString($profile['notes'], "Tier '$tier' notes must be a string (BR-9.2 client duties).");
        }
    }
}
