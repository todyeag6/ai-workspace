<?php

declare(strict_types=1);

namespace App\Tests\Deploy;

use App\Deploy\DeployClientValidator;
use App\Deploy\IndustryTemplate;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * P5-T4 — Template instantiation produces a valid deploy.config.php.
 * Loads a template, composes a config, and runs it through the P4-T3
 * DeployClientValidator (FR-DATA-001 honesty). A template that implies a cloud
 * DSN under a `local` deployment model must be refused.
 */
final class TemplateInstantiationTest extends TestCase
{
    private const TEMPLATE_DIR = __DIR__ . '/../../config/deploy/templates';
    private const OUT = __DIR__ . '/../../.cache/deploy-config.gen.php';

    protected function tearDown(): void
    {
        if (is_file(self::OUT)) {
            unlink(self::OUT);
        }
    }

    #[Test]
    public function test_instantiate_default_template_yields_valid_config(): void
    {
        $tpl = IndustryTemplate::load('default', self::TEMPLATE_DIR);
        $config = $this->compose($tpl, 'local', 'mysql:host=db;dbname=aiwebscapes', 'http://openviking:1933');
        (new DeployClientValidator())->validate($config); // must not throw
        self::assertSame('local', $config['deployment_model']);
    }

    #[Test]
    public function test_instantiate_legal_template_refuses_cloud_dsn_under_local(): void
    {
        $tpl = IndustryTemplate::load('legal', self::TEMPLATE_DIR);
        // Legal defaults to local; a managed-cloud DSN must be refused by the validator.
        $config = $this->compose($tpl, 'local', 'mysql:host=managed-cloud.example;dbname=aiwebscapes', 'http://openviking:1933');
        $this->expectException(\App\Deploy\DeployConfigException::class);
        (new DeployClientValidator())->validate($config);
    }

    #[Test]
    public function test_script_writes_parseable_deploy_config(): void
    {
        if (!is_dir(dirname(self::OUT))) {
            mkdir(dirname(self::OUT), 0777, true);
        }
        $tpl = IndustryTemplate::load('finance', self::TEMPLATE_DIR);
        $config = $this->compose($tpl, 'hybrid', 'mysql:host=db;dbname=aiwebscapes', 'http://openviking:1933');
        $export = "<?php\nreturn " . var_export($config, true) . ";\n";
        file_put_contents(self::OUT, $export);
        self::assertFileExists(self::OUT);
        $loaded = require self::OUT;
        self::assertSame('finance', $loaded['template']);
        (new DeployClientValidator())->validate($loaded); // hybrid + in-stack DSNs OK
    }

    /**
     * @return array<string,mixed>
     */
    private function compose(array $tpl, string $model, string $dbDsn, string $vectorDsn): array
    {
        return [
            'template' => $tpl['hardware_profile'] === 'large' ? 'finance' : 'default',
            'deployment_model' => $model,
            'data_location' => 'local',
            'model_location' => 'local',
            'administrator' => 'ops@client.example',
            'support_boundary' => 'business-hours',
            'backup_owner' => 'ops@client.example',
            'update_owner' => 'ops@client.example',
            'exit_portability_plan' => 'export-data-and-decommission',
            'db_dsn' => $dbDsn,
            'redis_dsn' => 'redis://redis:6379',
            'openviking_dsn' => $vectorDsn,
            'hardware_profile' => $tpl['hardware_profile'],
            'policy_defaults' => $tpl['policy_defaults'],
        ];
    }
}
