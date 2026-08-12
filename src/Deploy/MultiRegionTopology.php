<?php

/**
 * Multi-region topology + data-residency validator (P5-T9).
 *
 * Default SINGLE-REGION. Cross-region replication is deny-by-default (SEC-005):
 * enabled only when `justified: true` AND a residency allowlist is present, and
 * every declared region is in the allowlist. A `local` deployment model NEVER
 * permits cross-region replication (FR-DATA-001 — client data stays put).
 *
 * STATUS: PROPOSED — flip to RATIFIED only after owner sign-off; update
 * MultiRegionTopologyTest in the same commit. Immutable: built from config; throws
 * on invalid input so a bad topology cannot be constructed silently.
 */

declare(strict_types=1);

namespace App\Deploy;

use InvalidArgumentException;

final class MultiRegionTopology
{
    /**
     * @param list<string> $regions
     * @param list<string> $residencyAllowlist
     */
    private function __construct(
        private readonly bool $enabled,
        private readonly array $regions,
        private readonly bool $justified,
        private readonly array $residencyAllowlist,
        private readonly string $deploymentModel,
    ) {
    }

    /**
     * @param array{enabled?: bool, regions?: list<string>, justified?: bool, residency_allowlist?: list<string>, deployment_model?: string} $cfg
     *
     * @throws InvalidArgumentException On missing fields, unjustified enable, or a
     *                                  region not in the residency allowlist.
     */
    public static function fromArray(array $cfg): self
    {
        $enabled = (bool) ($cfg['enabled'] ?? false);
        /** @var list<string> $regions */
        $regions = array_map('strval', (array) ($cfg['regions'] ?? []));
        $justified = (bool) ($cfg['justified'] ?? false);
        /** @var list<string> $allow */
        $allow = array_map('strval', (array) ($cfg['residency_allowlist'] ?? []));
        $model = (string) ($cfg['deployment_model'] ?? 'hybrid');

        if ($enabled && !$justified) {
            throw new InvalidArgumentException('Multi-region enabled without justified: true (SEC-005 deny-by-default).');
        }
        if ($enabled && $allow === []) {
            throw new InvalidArgumentException('Multi-region enabled without a residency allowlist (SEC-005).');
        }
        foreach ($regions as $region) {
            if (!in_array($region, $allow, true)) {
                throw new InvalidArgumentException(sprintf('Region not in residency allowlist: %s', $region));
            }
        }

        return new self($enabled, $regions, $justified, $allow, $model);
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    /**
     * @return list<string>
     */
    public function regions(): array
    {
        return $this->regions;
    }

    /**
     * Cross-region replication allowed only when explicitly justified AND the
     * deployment model is not `local` (FR-DATA-001).
     */
    public function allowsCrossRegionReplication(): bool
    {
        return $this->enabled && $this->justified && $this->deploymentModel !== 'local';
    }

    /**
     * Explicit per-model check (falsification probe): a `local` model must never
     * replicate, even if multi-region is otherwise justified.
     */
    public function allowsCrossRegionReplicationForModel(string $model): bool
    {
        return $this->allowsCrossRegionReplication() && $model !== 'local';
    }

    public function isRegionAllowed(string $region): bool
    {
        return in_array($region, $this->residencyAllowlist, true);
    }
}
