<?php

declare(strict_types=1);

namespace App\Tests\Deploy;

use App\Deploy\LocalDataServices;
use App\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * P4-T8 — Local data-services validator (FR-DATA-001 / AC-006).
 * Fail-closed: a `local` deployment must keep relational + vector data on-prem
 * (not a managed-cloud DSN). Pure, no IO.
 */
final class LocalDataServicesValidatorTest extends TestCase
{
    private function cfg(string $model, string $dbDsn, string $vectorDsn): array
    {
        return [
            'deployment_model' => $model,
            'db_dsn' => $dbDsn,
            'openviking_dsn' => $vectorDsn,
        ];
    }

    #[Test]
    public function test_local_with_in_stack_dsns_resolves(): void
    {
        $v = new LocalDataServices();
        $r = $v->validate($this->cfg('local', 'mysql:host=db;dbname=aiwebscapes', 'http://openviking:1933'));
        self::assertSame('local', $r['deployment_model']);
    }

    #[Test]
    public function test_local_with_cloud_db_dsn_refused(): void
    {
        $v = new LocalDataServices();
        $this->expectException(\App\Deploy\DeployConfigException::class);
        $this->expectExceptionMessageMatches('/local.*cloud|cloud.*local/i');
        $v->validate($this->cfg('local', 'mysql:host=managed-cloud.example;dbname=aiwebscapes', 'http://openviking:1933'));
    }

    #[Test]
    public function test_local_with_cloud_vector_dsn_refused(): void
    {
        $v = new LocalDataServices();
        $this->expectException(\App\Deploy\DeployConfigException::class);
        $v->validate($this->cfg('local', 'mysql:host=db;dbname=aiwebscapes', 'http://managed-vector.example:1933'));
    }

    #[Test]
    public function test_hybrid_may_use_cloud_data_dsns(): void
    {
        $v = new LocalDataServices();
        $r = $v->validate($this->cfg('hybrid', 'mysql:host=managed-cloud.example;dbname=aiwebscapes', 'http://managed-vector.example:1933'));
        self::assertSame('hybrid', $r['deployment_model']);
    }
}
