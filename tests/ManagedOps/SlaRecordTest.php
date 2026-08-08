<?php

declare(strict_types=1);

namespace App\Tests\ManagedOps;

use App\ManagedOps\SlaRecord;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

/**
 * P2-T4 SLA measurement - the value object's breach logic and vocabulary.
 *
 * The regression value is the breach rule (observed > target is a breach;
 * exactly meeting the target is a pass) and the closed SLA-type vocabulary
 * (patch / incident_response / backup_restore_test, the BRD Table 4 security
 * KPIs). The breach flag the immutable row stores is derived here and must
 * agree with isBreached().
 *
 * © AI WebScapes 2026
 */
final class SlaRecordTest extends TestCase
{
    public function test_meeting_target_is_not_a_breach(): void
    {
        $sla = new SlaRecord('patch', 24.0, 24.0);
        self::assertFalse($sla->isBreached());
        self::assertSame(0, $sla->breachedFlag());
    }

    public function test_exceeding_target_is_a_breach(): void
    {
        $sla = new SlaRecord('patch', 24.0, 30.5);
        self::assertTrue($sla->isBreached());
        self::assertSame(1, $sla->breachedFlag());
    }

    public function test_under_target_is_a_pass(): void
    {
        $sla = new SlaRecord('incident_response', 4.0, 1.5);
        self::assertFalse($sla->isBreached());
    }

    public function test_rejects_unknown_type(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unknown SLA type "lateness"');
        new SlaRecord('lateness', 1.0, 0.5);
    }

    public function test_rejects_negative_hours(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('SLA hours must be non-negative');
        new SlaRecord('patch', -1.0, 0.5);
    }

    public function test_type_vocabulary_matches_baseline(): void
    {
        self::assertSame(
            ['patch', 'incident_response', 'backup_restore_test'],
            SlaRecord::types()
        );
    }
}
