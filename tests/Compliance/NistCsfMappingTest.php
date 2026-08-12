<?php

declare(strict_types=1);

namespace App\Tests\Compliance;

use App\Compliance\ControlMapping;
use App\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * P5-T6 — NIST CSF 2.0 mapping (docs fetched 2026-08-12: nist.gov/cyberframework,
 * CSF 2.0 Feb 2024, six Functions: Govern, Identify, Protect, Detect, Respond,
 * Recover). Every shipped SFR/AC must appear in at least one Function; the
 * framework version string is pinned so an unsourced edit fails CI.
 */
final class NistCsfMappingTest extends TestCase
{
    private function load(): ControlMapping
    {
        self::assertFileExists(__DIR__ . '/../../config/compliance/NIST_CSF_2_0.php');
        return ControlMapping::fromArray(require __DIR__ . '/../../config/compliance/NIST_CSF_2_0.php');
    }

    #[Test]
    public function test_framework_version_pinned(): void
    {
        $data = require __DIR__ . '/../../config/compliance/NIST_CSF_2_0.php';
        self::assertArrayHasKey('_meta', $data);
        self::assertSame('NIST-CSF-2.0', $data['_meta']['framework']);
        self::assertSame('2024-02', $data['_meta']['published']);
    }

    #[Test]
    public function test_every_shipped_control_appears_in_a_function(): void
    {
        $m = $this->load();
        foreach (['SFR-AUTH-001', 'SFR-SELF-001', 'SFR-SELF-003', 'AC-001', 'AC-002', 'AC-006', 'SEC-005'] as $ctrl) {
            self::assertNotEmpty(
                $m->lookup($ctrl),
                $ctrl . ' must map to at least one CSF 2.0 Function'
            );
        }
    }

    #[Test]
    public function test_mapping_uses_real_csf_2_0_functions(): void
    {
        $m = $this->load();
        $refs = [];
        foreach (['SFR-AUTH-001', 'SFR-SELF-001', 'SEC-005'] as $ctrl) {
            $refs[] = ($m->lookup($ctrl)['NIST_CSF_2_0'] ?? [])[0] ?? '';
        }
        // CSF 2.0 Function prefixes: GV (Govern), ID (Identify), PR (Protect),
        // DE (Detect), RS (Respond), RC (Recover).
        foreach ($refs as $ref) {
            self::assertMatchesRegularExpression('/^(GV|ID|PR|DE|RS|RC)\./', $ref);
        }
    }
}
