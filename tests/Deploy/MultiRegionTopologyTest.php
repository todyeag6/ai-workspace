<?php

declare(strict_types=1);

namespace App\Tests\Deploy;

use App\Deploy\MultiRegionTopology;
use App\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * P5-T9 — Region topology + residency validator (BRD Phase 5 #5: multi-region
 * "where justified"). Default-off: single region, disabled. Multi-region requires
 * an explicit `justified` flag + residency allowlist. Cross-region replication is
 * deny-by-default (SEC-005); a `local` deployment model never replicates (FR-DATA-001).
 */
final class MultiRegionTopologyTest extends TestCase
{
    #[Test]
    public function test_default_is_single_region_and_disabled(): void
    {
        $t = MultiRegionTopology::fromArray([
            'enabled' => false,
            'regions' => ['us-east'],
            'residency_allowlist' => ['us-east'],
        ]);
        self::assertFalse($t->isEnabled());
        self::assertSame(['us-east'], $t->regions());
    }

    #[Test]
    public function test_enabled_without_justification_refused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        MultiRegionTopology::fromArray([
            'enabled' => true,
            'regions' => ['us-east', 'eu-west'],
            'justified' => false,
            'residency_allowlist' => ['us-east', 'eu-west'],
        ]);
    }

    #[Test]
    public function test_justified_multi_region_accepted(): void
    {
        $t = MultiRegionTopology::fromArray([
            'enabled' => true,
            'regions' => ['us-east', 'eu-west'],
            'justified' => true,
            'residency_allowlist' => ['us-east', 'eu-west'],
        ]);
        self::assertTrue($t->isEnabled());
        self::assertTrue($t->allowsCrossRegionReplication());
    }

    #[Test]
    public function test_local_model_never_replicates_even_if_justified(): void
    {
        $t = MultiRegionTopology::fromArray([
            'enabled' => true,
            'regions' => ['us-east', 'eu-west'],
            'justified' => true,
            'residency_allowlist' => ['us-east', 'eu-west'],
            'deployment_model' => 'local',
        ]);
        self::assertFalse(
            $t->allowsCrossRegionReplicationForModel('local'),
            'Local deployment must never replicate across regions (FR-DATA-001).'
        );
    }

    #[Test]
    public function test_hybrid_model_may_replicate_when_justified(): void
    {
        $t = MultiRegionTopology::fromArray([
            'enabled' => true,
            'regions' => ['us-east', 'eu-west'],
            'justified' => true,
            'residency_allowlist' => ['us-east', 'eu-west'],
            'deployment_model' => 'hybrid',
        ]);
        self::assertTrue(
            $t->allowsCrossRegionReplicationForModel('hybrid'),
            'Hybrid may replicate to an allowlisted region.'
        );
    }

    #[Test]
    public function test_region_outside_allowlist_refused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        MultiRegionTopology::fromArray([
            'enabled' => true,
            'regions' => ['us-east', 'eu-west'],
            'justified' => true,
            'residency_allowlist' => ['us-east'], // eu-west not allowed
        ]);
    }

    #[Test]
    public function test_is_region_allowed_checks_allowlist(): void
    {
        $t = MultiRegionTopology::fromArray([
            'enabled' => true,
            'regions' => ['us-east', 'eu-west'],
            'justified' => true,
            'residency_allowlist' => ['us-east', 'eu-west'],
        ]);
        self::assertTrue($t->isRegionAllowed('eu-west'));
        self::assertFalse($t->isRegionAllowed('ap-south'));
    }
}
