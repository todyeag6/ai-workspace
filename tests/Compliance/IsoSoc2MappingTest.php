<?php

declare(strict_types=1);

namespace App\Tests\Compliance;

use App\Compliance\ControlMapping;
use App\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * P5-T7 — ISO/IEC 27001:2022 (Annex A, 93 controls: 5=Org, 6=People, 7=Physical,
 * 8=Technological) + SOC 2 TSC (Security/Availability/Confidentiality/Privacy/
 * Processing Integrity, AICPA 2017 + 2022 PoF) mappings. Docs fetched 2026-08-12.
 * SFRs map to >=1 Annex A control and >=1 TSC; version strings pinned.
 */
final class IsoSoc2MappingTest extends TestCase
{
    private function loadIso(): ControlMapping
    {
        self::assertFileExists(__DIR__ . '/../../config/compliance/ISO_27001_2022.php');
        return ControlMapping::fromArray(require __DIR__ . '/../../config/compliance/ISO_27001_2022.php');
    }

    private function loadSoc(): ControlMapping
    {
        self::assertFileExists(__DIR__ . '/../../config/compliance/SOC2_TSC.php');
        return ControlMapping::fromArray(require __DIR__ . '/../../config/compliance/SOC2_TSC.php');
    }

    #[Test]
    public function test_iso_version_pinned_and_maps_to_annex_a(): void
    {
        $data = require __DIR__ . '/../../config/compliance/ISO_27001_2022.php';
        self::assertSame('ISO-27001-2022', $data['_meta']['framework']);
        $m = $this->loadIso();
        $refs = $m->lookup('SFR-AUTH-001')['ISO_27001_2022'];
        self::assertMatchesRegularExpression('/^A\.(5|6|7|8)\./', $refs[0]);
    }

    #[Test]
    public function test_iso_every_control_maps_to_annex_a(): void
    {
        $m = $this->loadIso();
        foreach (['SFR-AUTH-001', 'SFR-SELF-001', 'SFR-SELF-003', 'AC-001', 'AC-002', 'AC-006', 'SEC-005'] as $ctrl) {
            $refs = $m->lookup($ctrl)['ISO_27001_2022'] ?? [];
            self::assertNotEmpty($refs, $ctrl . ' must map to an Annex A control');
            self::assertMatchesRegularExpression('/^A\.(5|6|7|8)\./', $refs[0]);
        }
    }

    #[Test]
    public function test_soc2_version_pinned_and_maps_to_tsc(): void
    {
        $data = require __DIR__ . '/../../config/compliance/SOC2_TSC.php';
        self::assertSame('SOC2-TSC-2017-2022', $data['_meta']['framework']);
        $m = $this->loadSoc();
        $refs = $m->lookup('SEC-005')['SOC2_TSC'];
        self::assertContains($refs[0], ['CC6.1', 'CC6.6', 'CC6.7']); // Common criteria (Security)
    }

    #[Test]
    public function test_soc2_every_control_maps_to_a_tsc(): void
    {
        $m = $this->loadSoc();
        foreach (['SFR-AUTH-001', 'SFR-SELF-001', 'SFR-SELF-003', 'AC-001', 'AC-002', 'AC-006', 'SEC-005'] as $ctrl) {
            $refs = $m->lookup($ctrl)['SOC2_TSC'] ?? [];
            self::assertNotEmpty($refs, $ctrl . ' must map to a SOC 2 TSC');
        }
    }
}
