<?php

declare(strict_types=1);

namespace App\Tests\ManagedOps;

use App\ManagedOps\SupportModel;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

/**
 * P2-T4 support model - the value object's tier vocabulary and shape.
 *
 * The regression value: an unknown tier is refused (BR-9.1 "support boundary"
 * must name a real commitment level, not a free string), and the allowed
 * tiers are the four ascending commitment levels the managed-service surface
 * offers. Contacts are carried verbatim (they are data, escaped downstream by
 * the assembler like every other report field).
 *
 * © AI WebScapes 2026
 */
final class SupportModelTest extends TestCase
{
    /**
     * @return list<array{role: string, channel: string, target: string}>
     */
    private function contacts(): array
    {
        return [
            ['role' => 'primary', 'channel' => 'pager', 'target' => '15m'],
            ['role' => 'security', 'channel' => 'email', 'target' => '1h'],
        ];
    }

    public function test_builds_a_valid_model(): void
    {
        $m = new SupportModel('standard', $this->contacts(), 'client owns hardware');
        self::assertSame('standard', $m->tier());
        self::assertCount(2, $m->contacts());
        self::assertSame('client owns hardware', $m->boundary());
    }

    public function test_rejects_unknown_tier(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unknown support tier "platinum"');
        new SupportModel('platinum', $this->contacts(), 'boundary');
    }

    public function test_tiers_are_ascending_commitment(): void
    {
        self::assertSame(
            ['basic', 'standard', 'premium', 'mission_critical'],
            SupportModel::tiers()
        );
    }
}
