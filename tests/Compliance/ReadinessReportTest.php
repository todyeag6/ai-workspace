<?php

declare(strict_types=1);

namespace App\Tests\Compliance;

use App\Compliance\ControlMapping;
use App\Compliance\ReadinessReport;
use App\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * P5-T8 — Compliance readiness report (BRD Phase 5 #4).
 * Aggregates NIST CSF 2.0 / ISO 27001:2022 / SOC 2 TSC mappings into a coverage
 * report: which frameworks are covered, and which mandatory internal controls are
 * NOT yet mapped (flagged, never omitted — fail-visible).
 */
final class ReadinessReportTest extends TestCase
{
    private function loadAll(): ControlMapping
    {
        $m = ControlMapping::fromArray(require __DIR__ . '/../../config/compliance/NIST_CSF_2_0.php');
        $iso = ControlMapping::fromArray(require __DIR__ . '/../../config/compliance/ISO_27001_2022.php');
        $soc = ControlMapping::fromArray(require __DIR__ . '/../../config/compliance/SOC2_TSC.php');
        return $m->merge($iso)->merge($soc);
    }

    #[Test]
    public function test_report_lists_covered_frameworks(): void
    {
        $report = new ReadinessReport($this->loadAll());
        $covered = $report->coveredFrameworks();
        self::assertContains('NIST_CSF_2_0', $covered);
        self::assertContains('ISO_27001_2022', $covered);
        self::assertContains('SOC2_TSC', $covered);
    }

    #[Test]
    public function test_every_shipped_control_is_mapped(): void
    {
        $report = new ReadinessReport($this->loadAll());
        self::assertEmpty($report->unmappedControls(), 'All mandatory controls should be mapped');
    }

    #[Test]
    public function test_unmapped_mandatory_control_is_flagged_not_omitted(): void
    {
        $m = $this->loadAll();
        $all = $m->all();
        unset($all['SFR-SELF-003']);
        $gap = ControlMapping::fromArray($all);
        $report = new ReadinessReport($gap);
        self::assertArrayHasKey('SFR-SELF-003', $report->unmappedControls());
        self::assertNotEmpty($report->unmappedControls()['SFR-SELF-003']);
    }
}
