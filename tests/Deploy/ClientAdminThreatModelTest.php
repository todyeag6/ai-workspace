<?php

declare(strict_types=1);

namespace App\Tests\Deploy;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * P4-T12 — STRIDE coverage for the Local/Hybrid Toolkit (Phase 4 threat model).
 * Count-free: asserts each STRIDE category is named and the new Phase 4 attack
 * surfaces (in-stack ollama/openviking egress, opt-in telemetry) are addressed.
 * Mirrors IncidentCoverageTest's keyword convention.
 */
final class ClientAdminThreatModelTest extends TestCase
{
    private const PATH = __DIR__ . '/../../docs/client-admin/THREAT_MODEL.md';

    private function read(): string
    {
        self::assertFileExists(self::PATH, 'Phase 4 STRIDE threat model missing.');
        $text = file_get_contents(self::PATH);
        self::assertIsString($text);
        return $text;
    }

    #[Test]
    public function test_all_six_stride_categories_named(): void
    {
        $text = $this->read();
        foreach (['Spoofing', 'Tampering', 'Repudiation', 'Information disclosure', 'Denial of service', 'Elevation of privilege'] as $cat) {
            self::assertStringContainsString($cat, $text, 'STRIDE category missing: ' . $cat);
        }
    }

    #[Test]
    public function test_phase4_local_services_threats_addressed(): void
    {
        $text = $this->read();
        // New attack surfaces introduced by Phase 4.
        self::assertStringContainsString('ollama', $text);
        self::assertStringContainsString('openviking', $text);
        self::assertStringContainsString('telemetry', $text);
        // Defence-in-depth posture held.
        self::assertStringContainsString('scanner_net', $text);
        self::assertStringContainsString('app_net', $text);
        self::assertStringContainsString('deny-by-default', $text);
    }
}
