<?php

declare(strict_types=1);

namespace App\Tests\Deploy;

use App\Deploy\IndustryTemplate;
use App\Deploy\DeployConfigException;
use App\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * P5-T3 — Industry template presets (BRD Phase 5 #2).
 * Each template composes a Phase-4 hardware tier + policy defaults with sector
 * notes. Pure config-contract test: every template must declare a valid
 * hardware_profile (small/medium/large) and the required policy keys; an unknown
 * template name is refused.
 */
final class IndustryTemplateTest extends TestCase
{
    private const DIR = __DIR__ . '/../../config/deploy/templates';

    #[Test]
    public function test_default_template_is_present_and_valid(): void
    {
        $t = IndustryTemplate::load('default', $this->dir());
        self::assertSame('medium', $t['hardware_profile']);
        self::assertArrayHasKey('policy_defaults', $t);
        self::assertArrayHasKey('sector_notes', $t);
    }

    #[Test]
    public function test_legal_template_binds_small_profile_with_data_residency(): void
    {
        $t = IndustryTemplate::load('legal', $this->dir());
        self::assertContains($t['hardware_profile'], ['small', 'medium', 'large']);
        // Legal sector: data residency must be explicit (FR-DATA-001 posture).
        self::assertArrayHasKey('data_residency', $t['policy_defaults']);
    }

    #[Test]
    public function test_healthcare_template_binds_medium_profile(): void
    {
        $t = IndustryTemplate::load('healthcare', $this->dir());
        self::assertSame('medium', $t['hardware_profile']);
        self::assertArrayHasKey('sector_notes', $t);
    }

    #[Test]
    public function test_finance_template_binds_large_profile(): void
    {
        $t = IndustryTemplate::load('finance', $this->dir());
        self::assertSame('large', $t['hardware_profile']);
    }

    #[Test]
    public function test_unknown_template_refused(): void
    {
        $this->expectException(DeployConfigException::class);
        IndustryTemplate::load('spaceship', $this->dir());
    }

    #[Test]
    public function test_every_template_declares_required_keys(): void
    {
        foreach (['default', 'legal', 'healthcare', 'finance'] as $name) {
            $t = IndustryTemplate::load($name, $this->dir());
            self::assertArrayHasKey('hardware_profile', $t, $name);
            self::assertArrayHasKey('policy_defaults', $t, $name);
            self::assertArrayHasKey('sector_notes', $t, $name);
            self::assertContains(
                $t['hardware_profile'],
                ['small', 'medium', 'large'],
                $name . ' must select a known hardware tier'
            );
        }
    }

    private function dir(): string
    {
        return self::DIR;
    }
}
