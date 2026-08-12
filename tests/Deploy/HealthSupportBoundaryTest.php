<?php

declare(strict_types=1);

namespace App\Tests\Deploy;

use App\Observability\Health;
use App\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * P4-T9 — Health reports the BR-9.1 support boundary (read-only).
 */
final class HealthSupportBoundaryTest extends TestCase
{
    #[Test]
    public function test_health_reports_support_boundary_fields(): void
    {
        // PDO/Redis are unused by supportBoundary(); pass harmless stubs.
        $health = new Health(
            $this->createStub(\PDO::class),
            $this->createStub(\Predis\ClientInterface::class)
        );
        $report = $health->supportBoundary(
            'business-hours',
            'ops@client.example',
            'ops@client.example'
        );
        self::assertSame('business-hours', $report['support_boundary']);
        self::assertSame('ops@client.example', $report['backup_owner']);
        self::assertSame('ops@client.example', $report['update_owner']);
    }
}
