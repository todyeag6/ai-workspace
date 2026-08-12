<?php

declare(strict_types=1);

namespace App\Deploy;

/**
 * Pure hardware-sizing selector + fit validator (P4-T2).
 *
 * Decides whether a host satisfies a named tier and which tier it can run.
 * No IO, no side effects — purely a function of the resource profile and the
 * ratifiable HARDWARE_SIZING policy. Same logic regardless of deployment model
 * (AC-006: cloud/hybrid/local share one control model).
 *
 * `fit()` answers "can this host run tier X"; `recommend()` returns the largest
 * tier the host satisfies. Input is caller-supplied host info, typed loosely
 * (array<string,mixed>) with safe defaults — this class exists to validate raw
 * input, so phpstan must not assume keys are present (phpstan-validator-typing).
 */
final class HardwareSizing
{
    /**
     * @param array<string,mixed> $available
     */
    public function fit(array $available, string $tier): bool
    {
        $profile = $this->profile($tier);
        if ($profile === null) {
            return false;
        }

        return (int) ($available['cpu_cores'] ?? 0) >= (int) ($profile['cpu_cores'] ?? 0)
            && (int) ($available['ram_gb'] ?? 0) >= (int) ($profile['ram_gb'] ?? 0)
            && (int) ($available['disk_gb'] ?? 0) >= (int) ($profile['disk_gb'] ?? 0);
    }

    /**
     * Largest tier the host satisfies; '' when nothing fits.
     * Iterates small->large and keeps the last that fits (so the kept tier is
     * the largest that still satisfies the host).
     *
     * @param array<string,mixed> $available
     */
    public function recommend(array $available): string
    {
        $best = '';
        foreach (['small', 'medium', 'large'] as $tier) {
            if ($this->fit($available, $tier)) {
                $best = $tier;
            }
        }
        return $best;
    }

    /**
     * @return array<string,mixed>|null
     */
    private function profile(string $tier): ?array
    {
        $policy = require __DIR__ . '/../../config/deploy/HARDWARE_SIZING.php';
        $profiles = $policy['profiles'] ?? [];
        $match = $profiles[$tier] ?? null;
        return ($match === null) ? null : (array) $match;
    }
}
