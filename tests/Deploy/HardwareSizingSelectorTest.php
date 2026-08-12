<?php

declare(strict_types=1);

namespace App\Tests\Deploy;

use App\Deploy\HardwareSizing;
use App\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * P4-T2 — Pure hardware-sizing selector + fit validator (AC-006: same controls
 * across deployment models). No DB, no side effects.
 */
final class HardwareSizingSelectorTest extends TestCase
{
    #[Test]
    public function test_fits_when_host_meets_tier_minimums(): void
    {
        $sizing = new HardwareSizing();
        self::assertTrue(
            $sizing->fit(['cpu_cores' => 4, 'ram_gb' => 8, 'disk_gb' => 80], 'medium'),
            'A 4c/8G/80G host meets the medium tier.'
        );
    }

    #[Test]
    public function test_does_not_fit_when_host_below_tier(): void
    {
        $sizing = new HardwareSizing();
        self::assertFalse(
            $sizing->fit(['cpu_cores' => 2, 'ram_gb' => 4, 'disk_gb' => 40], 'large'),
            'A small host must not satisfy the large tier.'
        );
    }

    #[Test]
    public function test_recommend_returns_largest_fitting_tier(): void
    {
        $sizing = new HardwareSizing();
        self::assertSame(
            'medium',
            $sizing->recommend(['cpu_cores' => 4, 'ram_gb' => 8, 'disk_gb' => 80]),
            'Largest tier that fits a 4c/8G/80G host is medium.'
        );
    }

    #[Test]
    public function test_recommend_falls_back_to_small_on_minimal_host(): void
    {
        $sizing = new HardwareSizing();
        self::assertSame(
            'small',
            $sizing->recommend(['cpu_cores' => 2, 'ram_gb' => 4, 'disk_gb' => 40])
        );
    }

    #[Test]
    public function test_unknown_tier_never_fits(): void
    {
        $sizing = new HardwareSizing();
        self::assertFalse($sizing->fit(['cpu_cores' => 64, 'ram_gb' => 256, 'disk_gb' => 4096], 'xl'));
    }
}
