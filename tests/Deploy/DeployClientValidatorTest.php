<?php

declare(strict_types=1);

namespace App\Tests\Deploy;

use App\Deploy\DeployClientValidator;
use App\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * P4-T3 — Fail-closed client deploy-config validator (BR-9.1, FR-DATA-001).
 * Pure: takes a config array, returns a resolved map or throws. No IO.
 */
final class DeployClientValidatorTest extends TestCase
{
    /**
     * Minimal valid config for a local deployment.
     * @return array<string,string>
     */
    private function validLocal(): array
    {
        return [
            'deployment_model' => 'local',
            'data_location' => 'client-datacenter',
            'model_location' => 'client-datacenter',
            'administrator' => 'jane@client.example',
            'support_boundary' => 'business-hours',
            'backup_owner' => 'ops@client.example',
            'update_owner' => 'ops@client.example',
            'exit_portability_plan' => 'export via migrate.php',
            'db_dsn' => 'mysql:host=localhost;dbname=aiwebscapes',
            'redis_dsn' => 'tcp://localhost:6379',
        ];
    }

    #[Test]
    public function test_valid_local_config_resolves(): void
    {
        $v = new DeployClientValidator();
        $resolved = $v->validate($this->validLocal());
        self::assertSame('local', $resolved['deployment_model']);
        self::assertSame('client-datacenter', $resolved['data_location']);
        self::assertArrayHasKey('config_version', $resolved);
    }

    #[Test]
    public function test_missing_required_field_refuses(): void
    {
        $v = new DeployClientValidator();
        $cfg = $this->validLocal();
        unset($cfg['backup_owner']);
        $this->expectException(\App\Deploy\DeployConfigException::class);
        $this->expectExceptionMessageMatches('/backup_owner/');
        $v->validate($cfg);
    }

    #[Test]
    public function test_local_deploy_with_cloud_db_dsn_refused(): void
    {
        // FR-DATA-001 / BR-9.2 honesty: a local deployment must not silently
        // put client data on a managed cloud DSN.
        $v = new DeployClientValidator();
        $cfg = $this->validLocal();
        $cfg['db_dsn'] = 'mysql:host=managed-cloud.provider.example;dbname=aiwebscapes';
        $this->expectException(\App\Deploy\DeployConfigException::class);
        $this->expectExceptionMessageMatches('/local.*cloud|cloud.*local/i');
        $v->validate($cfg);
    }

    #[Test]
    public function test_hybrid_deploy_may_use_cloud_db_dsn(): void
    {
        $v = new DeployClientValidator();
        $cfg = $this->validLocal();
        $cfg['deployment_model'] = 'hybrid';
        $cfg['data_location'] = 'client-datacenter';
        $cfg['db_dsn'] = 'mysql:host=managed-cloud.provider.example;dbname=aiwebscapes';
        $resolved = $v->validate($cfg);
        self::assertSame('hybrid', $resolved['deployment_model']);
    }

    #[Test]
    public function test_unknown_deployment_model_refused(): void
    {
        $v = new DeployClientValidator();
        $cfg = $this->validLocal();
        $cfg['deployment_model'] = 'spaceship';
        $this->expectException(\App\Deploy\DeployConfigException::class);
        $v->validate($cfg);
    }
}
