<?php

declare(strict_types=1);

namespace App\Tests\Compliance;

use App\Compliance\ControlMapping;
use App\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * P5-T5 — Generic compliance control-mapping engine (BRD Phase 5 #4).
 * Maps an internal control id (SFR/AC/policy) to external framework control refs.
 * Framework-agnostic: NIST CSF 2.0 / ISO 27001:2022 / SOC 2 are just data.
 * Pure: add/lookup mapping; unknown framework refused; duplicate internal id refused.
 */
final class ControlMappingTest extends TestCase
{
    #[Test]
    public function test_add_and_lookup_mapping(): void
    {
        $m = new ControlMapping();
        $m->add('SFR-AUTH-001', 'NIST_CSF_2_0', 'PR.AA-01');
        self::assertSame(['NIST_CSF_2_0' => ['PR.AA-01']], $m->lookup('SFR-AUTH-001'));
    }

    #[Test]
    public function test_unknown_framework_refused(): void
    {
        $m = new ControlMapping();
        $this->expectException(\InvalidArgumentException::class);
        $m->add('SFR-AUTH-001', 'MADE_UP_FW', 'X.1');
    }

    #[Test]
    public function test_duplicate_internal_control_refused(): void
    {
        $m = new ControlMapping();
        $m->add('SFR-AUTH-001', 'NIST_CSF_2_0', 'PR.AA-01');
        $this->expectException(\RuntimeException::class);
        $m->add('SFR-AUTH-001', 'NIST_CSF_2_0', 'PR.AA-01'); // same id twice
    }

    #[Test]
    public function test_loads_from_config_array(): void
    {
        $m = ControlMapping::fromArray([
            'SFR-AUTH-001' => ['NIST_CSF_2_0' => ['PR.AA-01'], 'ISO_27001_2022' => ['A.5.15']],
        ]);
        self::assertSame(['PR.AA-01'], $m->lookup('SFR-AUTH-001')['NIST_CSF_2_0']);
        self::assertSame(['A.5.15'], $m->lookup('SFR-AUTH-001')['ISO_27001_2022']);
    }

    #[Test]
    public function test_known_frameworks_are_the_verified_official_set(): void
    {
        // Grounded in docs fetched 2026-08-12: NIST CSF 2.0, ISO/IEC 27001:2022,
        // SOC 2 TSC (2017 + 2022 PoF). No invented frameworks.
        self::assertSame(
            ['NIST_CSF_2_0', 'ISO_27001_2022', 'SOC2_TSC'],
            ControlMapping::knownFrameworks()
        );
    }
}
