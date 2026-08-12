<?php

/**
 * Local data-services validator (P4-T8).
 *
 * Fail-closed: a `local` deployment must keep relational (MySQL) and vector
 * (OpenViking) data on-premises. A managed-cloud DSN under local is refused
 * (FR-DATA-001 / BR-9.2 honesty). Hybrid/cloud may use off-prem data services
 * under the same control model (AC-006). Pure — no IO.
 */

declare(strict_types=1);

namespace App\Deploy;

final class LocalDataServices
{
    /** @var list<string> Allowed deployment models (AC-006). */
    private const MODELS = ['cloud', 'hybrid', 'client-cloud', 'local'];

    /**
     * @param array<string,mixed> $config
     * @return array<string,mixed>
     *
     * @throws DeployConfigException When a `local` deployment points data/vector
     *                                DSNs at a managed-cloud host.
     */
    public function validate(array $config): array
    {
        $model = $config['deployment_model'] ?? null;
        if (!is_string($model) || !in_array($model, self::MODELS, true)) {
            throw new DeployConfigException(sprintf('Unknown deployment_model: %s', (string) $model));
        }

        if ($model === 'local') {
            $db = (string) ($config['db_dsn'] ?? '');
            $vector = (string) ($config['openviking_dsn'] ?? '');
            if ($this->isManagedCloudDsn($db) || $this->isManagedCloudDsn($vector)) {
                throw new DeployConfigException(
                    'Local deployment must not use a managed-cloud data/vector DSN (FR-DATA-001).'
                );
            }
        }

        return $config;
    }

    private function isManagedCloudDsn(string $dsn): bool
    {
        if ($dsn === '') {
            return false;
        }
        if (preg_match('/host=([^;]+)/i', $dsn, $m) === 1) {
            $host = strtolower(trim($m[1]));
        } elseif (preg_match('#https?://([^:/]+)#i', $dsn, $m) === 1) {
            $host = strtolower(trim($m[1]));
        } else {
            return false;
        }
        if ($host === 'localhost' || $host === '127.0.0.1' || $host === '::1' || $host === 'db' || $host === 'openviking') {
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
