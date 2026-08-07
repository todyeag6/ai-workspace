<?php

declare(strict_types=1);

namespace App\Observability;

use PDO;
use Predis\ClientInterface;
use Throwable;

/**
 * Dependency health probe (FR-OBS-001).
 *
 * Reports the status of each external dependency the platform actually relies
 * on - at minimum the database and Redis. The report is FAIL-VISIBLE, never
 * fail-silent: when a dependency is unreachable the entry says so (ok=false
 * with the error) rather than throwing or being omitted, so an operator sees
 * the truth during an incident.
 *
 * Each probe is isolated in its own try/catch so one broken dependency cannot
 * prevent the others from being reported.
 *
 * © AI WebScapes 2026
 */
class Health
{
    public function __construct(
        private PDO $pdo,
        private ClientInterface $redis
    ) {
    }

    /**
     * @return array{db: array{ok: bool, error?: string}, redis: array{ok: bool, error?: string}}
     */
    public function check(): array
    {
        return [
            'db' => $this->probeDb(),
            'redis' => $this->probeRedis(),
        ];
    }

    /**
     * @return array{ok: bool, error?: string}
     */
    protected function probeDb(): array
    {
        try {
            $statement = $this->pdo->prepare('SELECT 1');
            if ($statement === false) {
                return ['ok' => false, 'error' => 'database prepare returned no statement'];
            }
            $statement->execute();
            $statement->fetchColumn();

            return ['ok' => true];
        } catch (Throwable $error) {
            return ['ok' => false, 'error' => $error->getMessage()];
        }
    }

    /**
     * @return array{ok: bool, error?: string}
     */
    protected function probeRedis(): array
    {
        try {
            $this->redis->ping();

            return ['ok' => true];
        } catch (Throwable $error) {
            return ['ok' => false, 'error' => $error->getMessage()];
        }
    }
}
