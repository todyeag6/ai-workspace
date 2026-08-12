<?php

declare(strict_types=1);

namespace App\Deploy;

/**
 * Fail-closed client deploy-config validator (P4-T3).
 *
 * Validates the BR-9.1 deployment record (data/model location, administrator,
 * support boundary, backup owner, update owner, exit/portability plan) and the
 * FR-DATA-001 honesty guard: a `local` deployment must not resolve client data
 * to a managed cloud DSN. Pure — no IO; the CLI script (scripts/deploy-client.php)
 * is the only thing that touches disk.
 */
final class DeployClientValidator
{
    /** @var list<string> BR-9.1 required fields. */
    private const REQUIRED = [
        'deployment_model',
        'data_location',
        'model_location',
        'administrator',
        'support_boundary',
        'backup_owner',
        'update_owner',
        'exit_portability_plan',
        'db_dsn',
        'redis_dsn',
    ];

    /** @var list<string> Allowed deployment models (AC-006: same models, one control set). */
    private const MODELS = ['cloud', 'hybrid', 'client-cloud', 'local'];

    /**
     * @param array<string,mixed> $config
     * @return array<string,mixed> The validated, resolved config (adds config_version).
     *
     * @throws DeployConfigException When a required field is absent/blank or a
     *                               control rule (FR-DATA-001) is violated.
     */
    public function validate(array $config): array
    {
        foreach (self::REQUIRED as $key) {
            $value = $config[$key] ?? '';
            if ($value === '') {
                throw new DeployConfigException(sprintf('Missing required deploy field: %s', $key));
            }
        }

        $model = (string) $config['deployment_model'];
        if (!in_array($model, self::MODELS, true)) {
            throw new DeployConfigException(sprintf('Unknown deployment_model: %s', $model));
        }

        // FR-DATA-001 / BR-9.2 honesty guard: local deployment must keep client
        // data local. A managed-cloud hostname in db_dsn under local = refuse.
        if ($model === 'local' && $this->isManagedCloudDsn((string) $config['db_dsn'])) {
            throw new DeployConfigException(
                'Local deployment must not use a managed-cloud data DSN (FR-DATA-001).'
            );
        }

        $resolved = $config;
        $resolved['config_version'] = 'deploy-client-2026-08-12';
        return $resolved;
    }

    private function isManagedCloudDsn(string $dsn): bool
    {
        // Conservative: a hostname that is not localhost / an RFC1918 / .local
        // private literal is treated as managed-cloud for the local guard.
        if (preg_match('/host=([^;]+)/i', $dsn, $m) !== 1) {
            return false;
        }
        $host = strtolower(trim($m[1]));
        if ($host === 'localhost' || $host === '127.0.0.1' || $host === '::1') {
            return false;
        }
        // In-stack service hostnames are local by definition (compose service names).
        if (in_array($host, ['db', 'redis', 'openviking', 'ollama'], true)) {
            return false;
        }
        if (preg_match('/\.(local|internal|svc|cluster)$/', $host) === 1) {
            return false;
        }
        if (preg_match('/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/', $host) === 1) {
            return false;
        }
        return true;
    }
}
